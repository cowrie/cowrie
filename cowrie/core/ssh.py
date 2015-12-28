# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os

from zope.interface import implementer

import twisted
from twisted.conch.interfaces import ISFTPFile, ISFTPServer, ISession
from twisted.conch.ssh import session
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh import forwarding
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls
from twisted.python import log
from twisted.conch.ssh.common import getNS

from cowrie.core import pwd
from cowrie.core import protocol



class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        #self.__dict__['request_auth_agent_req@openssh.com'] = self.request_agent


    def request_env(self, data):
        """
        """
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg(eventid='COW0013', format='request_env: %(name)s=%(value)s',
            name=name, value=value)
        # Environment variables come after shell or before exec command
        if self.session:
            self.session.environ[name] = value
        return 0


    def request_agent(self, data):
        """
        """
        log.msg('request_agent: %s' % (repr(data),))
        return 0


    def request_x11_req(self, data):
        """
        """
        log.msg('request_x11: %s' % (repr(data),))
        return 0


    def closed(self):
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        session.SSHSession.closed(self)


    def sendEOF(self):
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)


    def sendClose(self):
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)


    def channelClosed(self):
        """
        """
        log.msg("Called channelClosed in SSHSession")



@implementer(ISession)
class SSHSessionForCowrieUser:
    """
    """

    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """
        self.protocol = None
        self.avatar = avatar
        self.server = avatar.server
        self.cfg = avatar.cfg
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username
        self.environ = {
            'LOGNAME': self.username,
            'USER': self.username,
            'HOME': self.avatar.home}
        if self.uid==0:
            self.environ['PATH']='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        else:
            self.environ['PATH']='/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'

    def openShell(self, processprotocol):
        """
        """
        self.protocol = protocol.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, self)
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))


    def getPty(self, terminal, windowSize, attrs):
        """
        """
        self.environ['TERM'] = terminal
        log.msg(eventid='COW0010', width=windowSize[0], height=windowSize[1],
            format='Terminal Size: %(width)s %(height)s')
        self.windowSize = windowSize
        return None


    def execCommand(self, processprotocol, cmd):
        """
        """
        self.protocol = protocol.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd)
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))


    def closed(self):
        """
        this is reliably called on both logout and disconnect
        we notify the protocol here we lost the connection
        """
        if self.protocol:
            self.protocol.connectionLost("disconnected")
            self.protocol = None


    def eofReceived(self):
        """
        """
        if self.protocol:
            self.protocol.eofReceived()


    def windowChanged(self, windowSize):
        """
        """
        self.windowSize = windowSize



@implementer(ISFTPFile)
class CowrieSFTPFile:
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
            log.msg(eventid='COW0015', format='Data upload limit reached')
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



class CowrieSFTPDirectory:
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
            longname = twisted.conch.ls.lsLine(f, s)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)


    def close(self):
        """
        """
        self.files = []



@implementer(ISFTPServer)
class SFTPServerForCowrieUser:
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
        log.msg("SFTP realPath: %s" % (path,))
        return self.fs.realpath(self._absPath(path))


    def extendedRequest(self, extName, extData):
        """
        """
        raise NotImplementedError


def CowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    """
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg(eventid='COW0014', format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s',
            dst_ip=remoteHP[0], dst_port=remoteHP[1])
    return CowrieConnectForwardingChannel(remoteHP,
       remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket,
       avatar=avatar)



class CowrieConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    """
    def channelOpen(self, specificData):
        """
        """
        pass


    def dataReceived(self, data):
        """
        """
        log.msg(eventid='COW0015',
            format='direct-tcp forward to %(dst_ip)s:%(dst_port)s with data %(data)s',
            dst_ip=self.hostport[0], dst_port=self.hostport[1], data=repr(data))
        self._close("Connection refused")

# vim: set et sw=4 et:
