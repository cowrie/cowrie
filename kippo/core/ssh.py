# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import twisted
from twisted.cred import portal
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport, filetransfer, forwarding
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls
from twisted.python import log, components
from zope.interface import implements



import os
import copy
import time
import ConfigParser

from kippo.core import ttylog, utils, fs
from kippo.core.config import config
import kippo.core.auth
import kippo.core.honeypot
import kippo.core.ssh
import kippo.core.protocol
from kippo import core

from twisted.conch.ssh.common import NS, getNS
class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        cfg = config()
        if not cfg.has_option('honeypot', 'banner_file'):
            return
        try:
            data = file(cfg.get('honeypot', 'banner_file')).read()
        except IOError:
            print 'Banner file %s does not exist!' % \
                cfg.get('honeypot', 'banner_file')
            return
        if not data or not len(data.strip()):
            return
        data = '\r\n'.join(data.splitlines() + [''])
        self.transport.sendPacket(
            userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))
        self.bannerSent = True

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

# As implemented by Kojoney
class HoneyPotSSHFactory(factory.SSHFactory):
    services = {
        'ssh-userauth': HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.SSHConnection,
        }

    # Special delivery to the loggers to avoid scope problems
    def logDispatch(self, sessionid, msg):
        for dblog in self.dbloggers:
            dblog.logDispatch(sessionid, msg)

    def __init__(self):
        cfg = config()

        # protocol^Wwhatever instances are kept here for the interact feature
        self.sessions = {}

        # for use by the uptime command
        self.starttime = time.time()

        # load db loggers
        self.dbloggers = []
        for x in cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            dbengine = 'database_' + engine
            lcfg = ConfigParser.ConfigParser()
            lcfg.add_section(dbengine)
            for i in cfg.options(x):
                lcfg.set(dbengine, i, cfg.get(x, i))
            lcfg.add_section('honeypot')
            for i in cfg.options('honeypot'):
                lcfg.set('honeypot', i, cfg.get('honeypot', i))
            print 'Loading dblog engine: %s' % (engine,)
            dblogger = __import__(
                'kippo.dblog.%s' % (engine,),
                globals(), locals(), ['dblog']).DBLogger(lcfg)
            log.startLoggingWithObserver(dblogger.emit, setStdout=False)
            self.dbloggers.append(dblogger)

    def buildProtocol(self, addr):
        cfg = config()

        # FIXME: try to mimic something real 100%
        t = HoneyPotTransport()

        if cfg.has_option('honeypot', 'ssh_version_string'):
            t.ourVersionString = cfg.get('honeypot','ssh_version_string')
        else:
            t.ourVersionString = "SSH-2.0-OpenSSH_5.1p1 Debian-5"

        t.supportedPublicKeys = self.privateKeys.keys()

        self.primes = primes.parseModuliFile('/etc/ssh/moduli')
        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        # reorder supported ciphers to resemble current openssh more
        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc' ]
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = [ 'hmac-md5', 'hmac-sha1']

        t.factory = self
        return t

class HoneyPotRealm:
    implements(portal.IRealm)

    def __init__(self):
        # I don't know if i'm supposed to keep static stuff here
        self.env = core.honeypot.HoneyPotEnvironment()

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception, "No supported interfaces found."

class HoneyPotTransport(transport.SSHServerTransport):

    hadVersion = False

    def connectionMade(self):
        print 'New connection: %s:%s (%s:%s) [session: %d]' % \
            (self.transport.getPeer().host, self.transport.getPeer().port,
            self.transport.getHost().host, self.transport.getHost().port,
            self.transport.sessionno)
        self.interactors = []
        self.logintime = time.time()
        self.ttylog_open = False
        transport.SSHServerTransport.connectionMade(self)

    def sendKexInit(self):
        # Don't send key exchange prematurely
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def dataReceived(self, data):
        transport.SSHServerTransport.dataReceived(self, data)
        # later versions seem to call sendKexInit again on their own
        if twisted.version.major < 11 and \
                not self.hadVersion and self.gotVersion:
            self.sendKexInit()
            self.hadVersion = True

    def ssh_KEXINIT(self, packet):
        print 'Remote SSH version: %s' % (self.otherVersionString,)
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def lastlogExit(self):
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = utils.durationHuman(time.time() - self.logintime)
        clientIP = self.transport.getPeer().host
        utils.addToLastlog('root\tpts/0\t%s\t%s - %s (%s)' % \
            (clientIP, starttime, endtime, duration))

    # this seems to be the only reliable place of catching lost connection
    def connectionLost(self, reason):
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        self.lastlogExit()
        if self.ttylog_open:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False
        transport.SSHServerTransport.connectionLost(self, reason)

    def sendDisconnect(self, reason, desc):
        """
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg('Disconnecting with error, code %s\nreason: %s' % \
                (reason, desc))
            self.transport.loseConnection()

class HoneyPotSSHSession(session.SSHSession):
    def request_env(self, data):
        print 'request_env: %s' % (repr(data))


class HoneyPotAvatar(avatar.ConchUser):
    implements(conchinterfaces.ISession)


    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.channelLookup.update({'session': HoneyPotSSHSession})
        self.channelLookup['direct-tcpip'] = KippoOpenConnectForwardingClient

        userdb = core.auth.UserDB()
        self.uid = self.gid = userdb.getUID(self.username)

        # sftp support enabled only when option is explicitly set
        if self.env.cfg.has_option('honeypot', 'sftp_enabled'):
            if ( self.env.cfg.get('honeypot', 'sftp_enabled') == "true" ):
                self.subsystemLookup['sftp'] = filetransfer.FileTransferServer

        if not self.uid:
            self.home = '/root'
        else:
            self.home = '/home/' + username

    def openShell(self, protocol):
        serverProtocol = core.protocol.LoggingServerProtocol(
            core.protocol.HoneyPotInteractiveProtocol, self, self.env)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        print 'Terminal size: %s %s' % windowSize[0:2]
        self.windowSize = windowSize
        return None

    def execCommand(self, protocol, cmd):
        cfg = config()
        if not cfg.has_option('honeypot', 'exec_enabled') or \
                cfg.get('honeypot', 'exec_enabled').lower() not in \
                    ('yes', 'true', 'on'):
            print 'Exec disabled. Not executing command: "%s"' % cmd
            raise core.exceptions.NotEnabledException, \
                'exec_enabled not enabled in configuration file!'
            return

        print 'exec command: "%s"' % cmd
        serverProtocol = kippo.core.protocol.LoggingServerProtocol(
            kippo.core.protocol.HoneyPotExecProtocol, self, self.env, cmd)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def closed(self):
        pass

    def eofReceived(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize

def getRSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'rsa_public_key')
    private_key = cfg.get('honeypot', 'rsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new RSA keypair..."
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = keys.Key(rsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
        print "Done."
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

def getDSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'dsa_public_key')
    private_key = cfg.get('honeypot', 'dsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new DSA keypair..."
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = keys.Key(dsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
        print "Done."
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

class KippoSFTPFile:
    implements(conchinterfaces.ISFTPFile)

    def __init__(self, server, filename, flags, attrs):
        self.server = server
        self.filename = filename
        self.transfer_completed = 0
        self.bytes_written = 0
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
        if attrs.has_key("permissions"):
            mode = attrs["permissions"]
            del attrs["permissions"]
        else:
            mode = 0777
        fd = server.fs.open(filename, openFlags, mode)
        if attrs:
            self.server.setAttrs(filename, attrs)
        self.fd = fd

        # cache a copy of file in memory to read from in readChunk
        if flags & FXF_READ == FXF_READ:
            self.contents = self.server.fs.file_contents(self.filename)

    def close(self):
        if ( self.bytes_written > 0 ):
            self.server.fs.update_size(self.filename, self.bytes_written)
        return self.server.fs.close(self.fd)

    def readChunk(self, offset, length):
        return self.contents[offset:offset+length]

    def writeChunk(self, offset, data):
        self.server.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.server.fs.write(self.fd, data)
        self.bytes_written += len(data)

    def getAttrs(self):
        s = self.server.fs.fstat(self.fd)
        return self.server._getAttrs(s)

    def setAttrs(self, attrs):
        raise NotImplementedError

class KippoSFTPDirectory:

    def __init__(self, server, directory):
        self.server = server
        self.files = server.fs.listdir(directory)
        self.dir = directory

    def __iter__(self):
        return self

    def next(self):
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
        self.files = []

class KippoSFTPServer:
    implements(conchinterfaces.ISFTPServer)

    def __init__(self, avatar):
        self.avatar = avatar
        # FIXME we should not copy fs here, but do this at avatar instantiation
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.avatar.env.fs))

    def _absPath(self, path):
        home = self.avatar.home
        return os.path.abspath(os.path.join(home, path))

    def _setAttrs(self, path, attrs):
        if attrs.has_key("uid") and attrs.has_key("gid"):
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if attrs.has_key("permissions"):
            self.fs.chmod(path, attrs["permissions"])
        if attrs.has_key("atime") and attrs.has_key("mtime"):
            self.fs.utime(path, attrs["atime"], attrs["mtime"])

    def _getAttrs(self, s):
        return {
            "size" : s.st_size,
            "uid" : s.st_uid,
            "gid" : s.st_gid,
            "permissions" : s.st_mode,
            "atime" : int(s.st_atime),
            "mtime" : int(s.st_mtime)
        }

    def gotVersion(self, otherVersion, extData):
        return {}

    def openFile(self, filename, flags, attrs):
        print "SFTP openFile: %s" % filename
        return KippoSFTPFile(self, self._absPath(filename), flags, attrs)

    def removeFile(self, filename):
        print "SFTP removeFile: %s" % filename
        return self.fs.remove(self._absPath(filename))

    def renameFile(self, oldpath, newpath):
        print "SFTP renameFile: %s %s" % (oldpath, newpath)
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    def makeDirectory(self, path, attrs):
        print "SFTP makeDirectory: %s" % path
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)
        return

    def removeDirectory(self, path):
        print "SFTP removeDirectory: %s" % path
        return self.fs.rmdir(self._absPath(path))

    def openDirectory(self, path):
        print "SFTP OpenDirectory: %s" % path
        return KippoSFTPDirectory(self, self._absPath(path))

    def getAttrs(self, path, followLinks):
        print "SFTP getAttrs: %s" % path
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)

    def setAttrs(self, path, attrs):
        print "SFTP setAttrs: %s" % path
        path = self._absPath(path)
        return self._setAttrs(path, attrs)

    def readLink(self, path):
        print "SFTP readLink: %s" % path
        path = self._absPath(path)
        return self.fs.readlink(path)

    def makeLink(self, linkPath, targetPath):
        print "SFTP makeLink: %s" % path
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)

    def realPath(self, path):
        print "SFTP realPath: %s" % path
        return self.fs.realpath(self._absPath(path))

    def extendedRequest(self, extName, extData):
        raise NotImplementedError

components.registerAdapter( KippoSFTPServer, HoneyPotAvatar, conchinterfaces.ISFTPServer)

def KippoOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg( "connection attempt to %s:%i" % remoteHP )
    return None

# vim: set et sw=4 et:
