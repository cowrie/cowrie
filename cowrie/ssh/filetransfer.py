# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os

from zope.interface import implementer

import twisted
from twisted.conch.interfaces import ISFTPFile, ISFTPServer
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls
from twisted.python import log

import cowrie.core.pwd as pwd


@implementer(ISFTPFile)
class CowrieSFTPFile(object):
    """
    """

    def __init__(self, sftpserver, filename, flags, attrs):
        self.sftpserver = sftpserver
        self.filename = filename
        self.transfer_completed = 0
        self.bytes_written = 0

        try:
            self.bytesReceivedLimit = int(
                self.sftpserver.avatar.server.cfg.get('honeypot',
                    'download_limit_size'))
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
            mode = attrs["permissions"]
            del attrs["permissions"]
        else:
            mode = 0777
        fd = sftpserver.fs.open(filename, openFlags, mode)
        if attrs:
            self.sftpserver.setAttrs(filename, attrs)
        self.fd = fd

        # Cache a copy of file in memory to read from in readChunk
        if flags & FXF_READ == FXF_READ:
            self.contents = self.sftpserver.fs.file_contents(self.filename)


    def close(self):
        """
        """
        if (self.bytes_written > 0):
            self.sftpserver.fs.update_size(self.filename, self.bytes_written)
        return self.sftpserver.fs.close(self.fd)


    def readChunk(self, offset, length):
        """
        """
        return self.contents[offset:offset+length]


    def writeChunk(self, offset, data):
        """
        """
        self.bytes_written += len(data)
        if self.bytesReceivedLimit and self.bytes_written > self.bytesReceivedLimit:
            log.msg(eventid='cowrie.direct-tcpip.data', format='Data upload limit reached')
            raise filetransfer.SFTPError( filetransfer.FX_FAILURE, "Quota exceeded" )
        self.sftpserver.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.sftpserver.fs.write(self.fd, data)


    def getAttrs(self):
        """
        """
        s = self.sftpserver.fs.stat(self.filename)
        return self.sftpserver._getAttrs(s)


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
        else:
            s = self.server.fs.lstat(os.path.join(self.dir, f))
            s2 = self.server.fs.lstat(os.path.join(self.dir, f))
            s2.st_uid = pwd.Passwd(self.server.avatar.cfg).getpwuid(s.st_uid)["pw_name"]
            s2.st_gid = pwd.Group(self.server.avatar.cfg).getgrgid(s.st_gid)["gr_name"]
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
        self.fs = self.avatar.server.fs


    def _absPath(self, path):
        """
        """
        home = self.avatar.home
        return os.path.abspath(os.path.join(home, path))


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
        log.msg("SFTP openFile: %s" % (filename,))
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)


    def removeFile(self, filename):
        """
        """
        log.msg("SFTP removeFile: %s" % (filename,))
        return self.fs.remove(self._absPath(filename))


    def renameFile(self, oldpath, newpath):
        """
        """
        log.msg("SFTP renameFile: %s %s" % (oldpath, newpath))
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))


    def makeDirectory(self, path, attrs):
        """
        """
        log.msg("SFTP makeDirectory: %s" % (path,))
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)
        return


    def removeDirectory(self, path):
        """
        """
        log.msg("SFTP removeDirectory: %s" % (path,))
        return self.fs.rmdir(self._absPath(path))


    def openDirectory(self, path):
        """
        """
        log.msg("SFTP OpenDirectory: %s" % (path,))
        return CowrieSFTPDirectory(self, self._absPath(path))


    def getAttrs(self, path, followLinks):
        """
        """
        log.msg("SFTP getAttrs: %s" % (path,))
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)


    def setAttrs(self, path, attrs):
        """
        """
        log.msg("SFTP setAttrs: %s" % (path,))
        path = self._absPath(path)
        return self._setAttrs(path, attrs)


    def readLink(self, path):
        """
        """
        log.msg("SFTP readLink: %s" % (path,))
        path = self._absPath(path)
        return self.fs.readlink(path)


    def makeLink(self, linkPath, targetPath):
        """
        """
        log.msg("SFTP makeLink: %s %s" % (linkPath, targetPath))
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)


    def realPath(self, path):
        """
        """
        #log.msg("SFTP realPath: %s" % (path,))
        return self.fs.realpath(self._absPath(path))


    def extendedRequest(self, extName, extData):
        """
        """
        raise NotImplementedError

