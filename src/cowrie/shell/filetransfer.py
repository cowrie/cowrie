# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains ...
"""

from __future__ import annotations

import errno
import functools
import os
from collections.abc import Callable
from typing import Any, TypeVar, cast

import twisted.conch.ls
from twisted.conch.interfaces import ISFTPFile, ISFTPServer
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh.filetransfer import (
    FXF_APPEND,
    FXF_CREAT,
    FXF_EXCL,
    FXF_READ,
    FXF_TRUNC,
    FXF_WRITE,
)
from twisted.python import log
from twisted.python.compat import nativeString
from zope.interface import implementer

import twisted
from cowrie.core.config import CowrieConfig
from cowrie.shell import pwd
from cowrie.shell.fs import FileNotFound, PermissionDenied

F = TypeVar("F", bound=Callable[..., Any])


def translate_fs_errors(method: F) -> F:
    """Translate the emulated filesystem's exceptions into ``OSError`` at the
    SFTP boundary.

    ``HoneyPotFilesystem`` raises ``FileNotFound`` / ``PermissionDenied`` for
    some operations (a missing parent directory, a write under ``/proc`` ...).
    The conch SFTP server only understands ``OSError`` / ``SFTPError``; a bare
    cowrie exception reaches it as an unexpected error, logged as a critical
    traceback and reported to the client as a generic failure. Mapping them to
    the matching errno lets conch return ``FX_NO_SUCH_FILE`` /
    ``FX_PERMISSION_DENIED`` instead.
    """

    @functools.wraps(method)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except FileNotFound:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT)) from None
        except PermissionDenied:
            raise OSError(errno.EACCES, os.strerror(errno.EACCES)) from None

    return cast("F", wrapper)


@implementer(ISFTPFile)
class CowrieSFTPFile:
    """
    SFTPTFile
    """

    contents: bytes
    bytesReceivedLimit: int = CowrieConfig.getint(
        "honeypot", "download_limit_size", fallback=0
    )

    def __init__(self, sftpserver, filename, flags, attrs):
        self.sftpserver = sftpserver
        self.filename = filename
        self.bytesReceived: int = 0

        openFlags = 0
        if flags & FXF_READ == FXF_READ and flags & FXF_WRITE == 0:
            openFlags = os.O_RDONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == 0:
            openFlags = os.O_WRONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == FXF_READ:
            openFlags = os.O_RDWR
        if flags & FXF_APPEND == FXF_APPEND:
            openFlags |= os.O_APPEND
        if flags & FXF_CREAT == FXF_CREAT:
            openFlags |= os.O_CREAT
        if flags & FXF_TRUNC == FXF_TRUNC:
            openFlags |= os.O_TRUNC
        if flags & FXF_EXCL == FXF_EXCL:
            openFlags |= os.O_EXCL
        if "permissions" in attrs:
            filemode = attrs["permissions"]
            del attrs["permissions"]
        else:
            filemode = 0o777
        fd = sftpserver.fs.open(filename, openFlags, filemode)
        if attrs:
            self.sftpserver.setAttrs(filename, attrs)
        self.fd = fd

        # Cache a copy of file in memory to read from in readChunk
        if flags & FXF_READ == FXF_READ:
            self.contents = self.sftpserver.fs.file_contents(self.filename)

    def close(self):
        if self.bytesReceived > 0:
            self.sftpserver.fs.update_size(self.filename, self.bytesReceived)
        return self.sftpserver.fs.close(self.fd)

    def readChunk(self, offset: int, length: int) -> bytes:
        return self.contents[offset : offset + length]

    def writeChunk(self, offset: int, data: bytes) -> None:
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            raise filetransfer.SFTPError(filetransfer.FX_FAILURE, "Quota exceeded")
        self.sftpserver.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.sftpserver.fs.write(self.fd, data)

    def getAttrs(self):
        s = self.sftpserver.fs.stat(self.filename)
        return self.sftpserver.getAttrs(s)

    def setAttrs(self, attrs):
        raise NotImplementedError


class CowrieSFTPDirectory:
    def __init__(self, server, directory):
        self.server = server
        self.files = server.fs.listdir(directory)
        self.files = [".", "..", *self.files]
        self.dir = directory

    def __iter__(self):
        return self

    def __next__(self):
        try:
            f = self.files.pop(0)
        except IndexError:
            raise StopIteration from None

        if f == "..":
            directory = self.dir.strip().split("/")
            pdir = "/" + "/".join(directory[:-1])
            s1 = self.server.fs.lstat(pdir)
            s = self.server.fs.lstat(pdir)
            s1.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s1.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s1)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)
        elif f == ".":
            s1 = self.server.fs.lstat(self.dir)
            s = self.server.fs.lstat(self.dir)
            s1.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s1.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s1)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)
        else:
            s = self.server.fs.lstat(os.path.join(self.dir, f))
            s2 = self.server.fs.lstat(os.path.join(self.dir, f))
            s2.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s2.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s2)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)

    def close(self):
        self.files = []


@implementer(ISFTPServer)
class SFTPServerForCowrieUser:
    def __init__(self, avatar):
        self.avatar = avatar
        self.avatar.server.initFileSystem(self.avatar.home)
        self.fs = self.avatar.server.fs
        # Bind the session's event emitter so SFTP uploads are attributed.
        self.fs.events = self.avatar.conn.transport.events

    def _absPath(self, path):
        home = self.avatar.home
        return os.path.abspath(os.path.join(nativeString(home), nativeString(path)))

    def _setAttrs(self, path, attrs):
        if "uid" in attrs and "gid" in attrs:
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if "permissions" in attrs:
            self.fs.chmod(path, attrs["permissions"])
        if "atime" in attrs and "mtime" in attrs:
            self.fs.utime(path, attrs["atime"], attrs["mtime"])

    def _getAttrs(self, s):
        return {
            "size": s.st_size,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "permissions": s.st_mode,
            "atime": int(s.st_atime),
            "mtime": int(s.st_mtime),
        }

    def gotVersion(self, otherVersion, extData):
        return {}

    @translate_fs_errors
    def openFile(self, filename, flags, attrs):
        log.msg(f"SFTP openFile: {filename}")
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)

    @translate_fs_errors
    def removeFile(self, filename):
        log.msg(f"SFTP removeFile: {filename}")
        return self.fs.remove(self._absPath(filename))

    @translate_fs_errors
    def renameFile(self, oldpath, newpath):
        log.msg(f"SFTP renameFile: {oldpath} {newpath}")
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    @translate_fs_errors
    def makeDirectory(self, path, attrs):
        log.msg(f"SFTP makeDirectory: {path}")
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)

    @translate_fs_errors
    def removeDirectory(self, path):
        log.msg(f"SFTP removeDirectory: {path}")
        return self.fs.rmdir(self._absPath(path))

    @translate_fs_errors
    def openDirectory(self, path):
        log.msg(f"SFTP OpenDirectory: {path}")
        return CowrieSFTPDirectory(self, self._absPath(path))

    @translate_fs_errors
    def getAttrs(self, path, followLinks):
        log.msg(f"SFTP getAttrs: {path}")
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)

    @translate_fs_errors
    def setAttrs(self, path, attrs):
        log.msg(f"SFTP setAttrs: {path}")
        path = self._absPath(path)
        return self._setAttrs(path, attrs)

    @translate_fs_errors
    def readLink(self, path):
        log.msg(f"SFTP readLink: {path}")
        path = self._absPath(path)
        return self.fs.readlink(path)

    def makeLink(self, linkPath, targetPath):
        log.msg(f"SFTP makeLink: {linkPath} {targetPath}")
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)

    def realPath(self, path):
        return self.fs.realpath(self._absPath(path))

    def extendedRequest(self, extName, extData):
        raise NotImplementedError
