# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import os

from zope.interface import implementer

import twisted
from twisted.python import log
from twisted.python.compat import nativeString
from twisted.conch.interfaces import ISFTPFile, ISFTPServer
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls

import cowrie.shell.pwd as pwd
from cowrie.core.config import CONFIG


@implementer(ISFTPFile)
class CowrieSFTPFile(object):
    """
    """

    def __init__(self, sftpserver, filename, flags, attrs):
        self.sftpserver = sftpserver
        self.filename = filename
        self.transfer_completed = 0
        self.bytesReceived = 0

        try:
            self.bytesReceivedLimit = CONFIG.getint('honeypot', 'download_limit_size')
        except:
            self.bytesReceivedLimit = 0

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
        """
        """
        if self.bytesReceived > 0:
            self.sftpserver.fs.update_size(self.filename, self.bytesReceived)
        return self.sftpserver.fs.close(self.fd)


    def readChunk(self, offset, length):
        """
        """
        return self.contents[offset:offset+length]


    def writeChunk(self, offset, data):
        """
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            raise filetransfer.SFTPError(filetransfer.FX_FAILURE, "Quota exceeded")
        self.sftpserver.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.sftpserver.fs.write(self.fd, data)


    def getAttrs(self):
        """
        """
        s = self.sftpserver.fs.stat(self.filename)
        return self.sftpserver.getAttrs(s)


    def setAttrs(self, attrs):
        """
        """
        raise NotImplementedError



class CowrieSFTPDirectory(object):
    """
    """
    def __init__(self, server, directory):
        self.server = server
        self.files = server.fs.listdir(directory)
        self.files = [".", ".."]+self.files
        self.dir = directory


    def __iter__(self):
        """
        """
        return self


    def next(self):
        """
        """
        try:
            f = self.files.pop(0)
        except IndexError:
            raise StopIteration

        if f == "..":
            directory = self.dir.strip().split("/")
            pdir = "/" + "/".join(directory[:-1])
            s1 = self.server.fs.lstat(pdir)
            s = self.server.fs.lstat(pdir)
            s1.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s1.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s1)
            attrs = self.server._getAttrs(s)
            return(f, longname, attrs)
        elif f == ".":
            s1 = self.server.fs.lstat(self.dir)
            s = self.server.fs.lstat(self.dir)
            s1.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s1.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s1)
            attrs = self.server._getAttrs(s)
            return(f, longname, attrs)
        else:
            s = self.server.fs.lstat(os.path.join(self.dir, f))
            s2 = self.server.fs.lstat(os.path.join(self.dir, f))
            s2.st_uid = pwd.Passwd().getpwuid(s.st_uid)["pw_name"]
            s2.st_gid = pwd.Group().getgrgid(s.st_gid)["gr_name"]
            longname = twisted.conch.ls.lsLine(f, s2)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)

    def close(self):
        """
        """
        self.files = []



@implementer(ISFTPServer)
class SFTPServerForCowrieUser(object):
    """
    """

    def __init__(self, avatar):
        self.avatar = avatar
        self.avatar.server.initFileSystem()
        self.fs = self.avatar.server.fs


    def _absPath(self, path):
        """
        """
        home = self.avatar.home
        return os.path.abspath(os.path.join(nativeString(home),
          nativeString(path)))


    def _setAttrs(self, path, attrs):
        """
        """
        if "uid" in attrs and "gid" in attrs:
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if "permissions" in attrs:
            self.fs.chmod(path, attrs["permissions"])
        if "atime" in attrs and "mtime" in attrs:
            self.fs.utime(path, attrs["atime"], attrs["mtime"])


    def _getAttrs(self, s):
        """
        """
        return {
            "size": s.st_size,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "permissions": s.st_mode,
            "atime": int(s.st_atime),
            "mtime": int(s.st_mtime)
        }


    def gotVersion(self, otherVersion, extData):
        """
        """
        return {}


    def openFile(self, filename, flags, attrs):
        """
        """
        log.msg("SFTP openFile: {}".format(filename))
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)


    def removeFile(self, filename):
        """
        """
        log.msg("SFTP removeFile: {}".format(filename))
        return self.fs.remove(self._absPath(filename))


    def renameFile(self, oldpath, newpath):
        """
        """
        log.msg("SFTP renameFile: {} {}".format(oldpath, newpath))
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))


    def makeDirectory(self, path, attrs):
        """
        """
        log.msg("SFTP makeDirectory: {}".format(path))
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)
        return


    def removeDirectory(self, path):
        """
        """
        log.msg("SFTP removeDirectory: {}".format(path))
        return self.fs.rmdir(self._absPath(path))


    def openDirectory(self, path):
        """
        """
        log.msg("SFTP OpenDirectory: {}".format(path))
        return CowrieSFTPDirectory(self, self._absPath(path))


    def getAttrs(self, path, followLinks):
        """
        """
        log.msg("SFTP getAttrs: {}".format(path))
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)


    def setAttrs(self, path, attrs):
        """
        """
        log.msg("SFTP setAttrs: {}".format(path))
        path = self._absPath(path)
        return self._setAttrs(path, attrs)


    def readLink(self, path):
        """
        """
        log.msg("SFTP readLink: {}".format(path))
        path = self._absPath(path)
        return self.fs.readlink(path)


    def makeLink(self, linkPath, targetPath):
        """
        """
        log.msg("SFTP makeLink: {} {}".format(linkPath, targetPath))
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)


    def realPath(self, path):
        """
        """
        #log.msg("SFTP realPath: {}".format(path))
        return self.fs.realpath(self._absPath(path))


    def extendedRequest(self, extName, extData):
        """
        """
        raise NotImplementedError
