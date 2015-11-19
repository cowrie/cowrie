# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os
import time
import struct
import uuid

from zope.interface import implements

import twisted
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.conch.ssh import factory
from twisted.conch.ssh import userauth
from twisted.conch.ssh import keys
from twisted.conch.ssh import session
from twisted.conch.ssh import transport
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh import forwarding
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls
from twisted.python import log, components
from twisted.conch.openssh_compat import primes
from twisted.conch.ssh.common import NS, getNS
from twisted.internet import defer
from twisted.protocols.policies import TimeoutMixin

from cowrie.core import credentials
from cowrie.core import auth
from cowrie.core import connection
from cowrie.core import honeypot
from cowrie.core import protocol
from cowrie.core import server


class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):

    def serviceStarted(self):
        self.interfaceToMethod[credentials.IUsername] = 'none'
        self.interfaceToMethod[credentials.IUsernamePasswordIP] = 'password'
        self.interfaceToMethod[credentials.IPluggableAuthenticationModulesIP] = 'keyboard-interactive'
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False
        self._pamDeferred = None

    def sendBanner(self):
        if self.bannerSent:
            return
        self.bannerSent = True
        try:
            honeyfs = self.portal.realm.cfg.get('honeypot', 'contents_path')
            issuefile = honeyfs + "/etc/issue.net"
            data = file(issuefile).read()
        except IOError:
            return
        if not data or not len(data.strip()):
            return
        self.transport.sendPacket(
            userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

    def auth_none(self, packet):
        c = credentials.Username(self.user)
        src_ip = self.transport.transport.getPeer().host
        return self.portal.login(c, src_ip, conchinterfaces.IConchUser)

    # Overridden to pass src_ip to credentials.UsernamePasswordIP
    def auth_password(self, packet):
        password = getNS(packet[1:])[0]
        src_ip = self.transport.transport.getPeer().host
        c = credentials.UsernamePasswordIP(self.user, password, src_ip)
        return self.portal.login(c, src_ip,
            conchinterfaces.IConchUser).addErrback(self._ebPassword)

    def auth_keyboard_interactive(self, packet):
        """
        Keyboard interactive authentication.  No payload.  We create a
        PluggableAuthenticationModules credential and authenticate with our
        portal.

        Overridden to pass src_ip to credentials.PluggableAuthenticationModulesIP
        """
        if self._pamDeferred is not None:
            self.transport.sendDisconnect(
                    transport.DISCONNECT_PROTOCOL_ERROR,
                    "only one keyboard interactive attempt at a time")
            return defer.fail(error.IgnoreAuthentication())
        src_ip = self.transport.transport.getPeer().host
        c = credentials.PluggableAuthenticationModulesIP(self.user,
            self._pamConv, src_ip)
        return self.portal.login(c, src_ip,
            conchinterfaces.IConchUser).addErrback(self._ebPassword)

    def _pamConv(self, items):
        """
        Convert a list of PAM authentication questions into a
        MSG_USERAUTH_INFO_REQUEST.  Returns a Deferred that will be called
        back when the user has responses to the questions.

        @param items: a list of 2-tuples (message, kind).  We only care about
            kinds 1 (password) and 2 (text).
        @type items: C{list}
        @rtype: L{defer.Deferred}
        """
        resp = []
        for message, kind in items:
            if kind == 1: # password
                resp.append((message, 0))
            elif kind == 2: # text
                resp.append((message, 1))
            elif kind in (3, 4):
                return defer.fail(error.ConchError(
                    'cannot handle PAM 3 or 4 messages'))
            else:
                return defer.fail(error.ConchError(
                    'bad PAM auth kind %i' % kind))
        packet = NS('') + NS('') + NS('')
        packet += struct.pack('>L', len(resp))
        for prompt, echo in resp:
            packet += NS(prompt)
            packet += chr(echo)
        self.transport.sendPacket(userauth.MSG_USERAUTH_INFO_REQUEST, packet)
        self._pamDeferred = defer.Deferred()
        return self._pamDeferred

    def ssh_USERAUTH_INFO_RESPONSE(self, packet):
        """
        The user has responded with answers to PAMs authentication questions.
        Parse the packet into a PAM response and callback self._pamDeferred.
        Payload::
            uint32 numer of responses
            string response 1
            ...
            string response n
        """
        d, self._pamDeferred = self._pamDeferred, None

        try:
            resp = []
            numResps = struct.unpack('>L', packet[:4])[0]
            packet = packet[4:]
            while len(resp) < numResps:
                response, packet = getNS(packet)
                resp.append((response, 0))
            if packet:
                raise error.ConchError("%i bytes of extra data" % len(packet))
        except:
            d.errback(failure.Failure())
        else:
            d.callback(resp)


class HoneyPotSSHFactory(factory.SSHFactory):
    services = {
        'ssh-userauth': HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.CowrieSSHConnection,
        }

    # Special delivery to the loggers to avoid scope problems
    def logDispatch(self, *msg, **args):
        for dblog in self.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.output_plugins:
            output.logDispatch(*msg, **args)

    def __init__(self, cfg):
        self.cfg = cfg

    def startFactory(self):

        # interactive protocols are kept here for the interact feature
        self.sessions = {}

        # for use by the uptime command
        self.starttime = time.time()

        # load/create keys
        rsa_pubKeyString, rsa_privKeyString = getRSAKeys(self.cfg)
        dsa_pubKeyString, dsa_privKeyString = getDSAKeys(self.cfg)
        self.publicKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_pubKeyString),
          'ssh-dss': keys.Key.fromString(data=dsa_pubKeyString)}
        self.privateKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_privKeyString),
          'ssh-dss': keys.Key.fromString(data=dsa_privKeyString)}

        # load db loggers
        self.dbloggers = []
        for x in self.cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            try:
                dblogger = __import__(
                    'cowrie.dblog.%s' % (engine,),
                    globals(), locals(), ['dblog']).DBLogger(self.cfg)
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
                log.msg("Loaded dblog engine: %s" % (engine,))
            except:
                log.err()
                log.msg("Failed to load dblog engine: %s" % (engine,))

        # load output modules
        self.output_plugins = []
        for x in self.cfg.sections():
            if not x.startswith('output_'):
                continue
            engine = x.split('_')[1]
            try:
                output = __import__(
                    'cowrie.output.%s' % (engine,)
                    ,globals(), locals(), ['output']).Output(self.cfg)
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg('Loaded output plugin: %s' % (engine,))
            except:
                log.err()
                log.msg('Failed to load output plugin: %s' % (engine,))

        factory.SSHFactory.startFactory(self)

    def stopFactory(self):
        factory.SSHFactory.stopFactory(self)

    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        @type addr: L{twisted.internet.interfaces.IAddress} provider
        @param addr: The address at which the server will listen.

        @rtype: L{twisted.conch.ssh.SSHServerTransport}
        @return: The built transport.
        """

        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'

        # FIXME: try to mimic something real 100%
        t = HoneyPotTransport()

        if self.cfg.has_option('honeypot', 'ssh_version_string'):
            t.ourVersionString = self.cfg.get('honeypot', 'ssh_version_string')
        else:
            t.ourVersionString = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"

        t.supportedPublicKeys = self.privateKeys.keys()

        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError as err:
                pass

        if not self.primes:
            log.msg("Moduli not found, disabling diffie-hellman-group-exchange-sha1")
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        # reorder supported ciphers to resemble current openssh more
        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc']
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = ['hmac-md5', 'hmac-sha1']

        t.factory = self
        return t


class HoneyPotTransport(transport.SSHServerTransport, TimeoutMixin):
    """
    """

    def connectionMade(self):
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.transportId = uuid.uuid4().hex[:8]
        self.interactors = []

        log.msg(eventid='KIPP0001',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(sessionno)s]',
           src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           id=self.transportId, sessionno=self.transport.sessionno)

        self.transport.write('%s\r\n' % (self.ourVersionString,))
        self.currentEncryptions = transport.SSHCiphers('none', 'none', 'none', 'none')
        self.currentEncryptions.setKeys('', '', '', '', '', '')
        self.setTimeout(120)

    def sendKexInit(self):
        # Don't send key exchange prematurely
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if not '\n' in self.buf:
                return
            self.otherVersionString = self.buf.split('\n')[0].strip()
            if self.buf.startswith('SSH-'):
                self.gotVersion = True
                remoteVersion = self.buf.split('-')[1]
                if remoteVersion not in self.supportedVersions:
                    self._unsupportedVersionReceived(remoteVersion)
                    return
                i = self.buf.index('\n')
                self.buf = self.buf[i+1:]
                self.sendKexInit()
            else:
                self.transport.write('Protocol mismatch.\n')
                log.msg('Bad protocol version identification: %s' % (self.otherVersionString))
                self.transport.loseConnection()
                return
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

        # later versions seem to call sendKexInit again on their own
        if twisted.version.major < 11 and \
                not self._hadVersion and self.gotVersion:
            self.sendKexInit()
            self._hadVersion = True

    def ssh_KEXINIT(self, packet):
        k = getNS(packet[16:], 10)
        strings, rest = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, encSC, macCS, macSC, compCS, compSC, langCS, langSC) = [s.split(',') for s in strings]
        log.msg(eventid='KIPP0009', version=self.otherVersionString,
            kexAlgs=kexAlgs, keyAlgs=keyAlgs, encCS=encCS, macCS=macCS,
            compCS=compCS, format='Remote SSH version: %(version)s')

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self):
        log.msg( "Authentication Timeout reached" )
        self.transport.loseConnection()

    def setService(self, service):
        """
        Remove login grace timeout
        """
        if service.name == "ssh-connection":
            self.setTimeout(None)
        transport.SSHServerTransport.setService(self, service)

    # this seems to be the only reliable place of catching lost connection
    def connectionLost(self, reason):
        self.setTimeout(None)
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        transport.SSHServerTransport.connectionLost(self, reason)
        self.transport.connectionLost(reason)
        self.transport = None
        log.msg(eventid='KIPP0011', format='Connection lost')

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Packet corrupt\n')
            log.msg('[SERVER] - Disconnecting with error, code %s\nreason: %s' % (reason, desc))
            self.transport.loseConnection()


class HoneyPotSSHSession(session.SSHSession):
    """
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        self.__dict__['request_auth_agent_req@openssh.com'] = self.request_agent

    def request_env(self, data):
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg(eventid='KIPP0013', format='request_env: %(name)s=%(value)s', name=name, value=value)
        return 0

    def request_agent(self, data):
        log.msg('request_agent: %s' % repr(data))
        return 0

    def request_x11_req(self, data):
        log.msg('request_x11: %s' % repr(data))
        return 0

    # this is reliably called on session close/disconnect and calls the avatar
    def closed(self):
        session.SSHSession.closed(self)

    # utility function to request to send EOF for this session
    def sendEOF(self):
        self.conn.sendEOF(self)

    # utility function to request to send close for this session
    def sendClose(self):
        self.conn.sendClose(self)

    def loseConnection(self):
        self.conn.sendRequest(self, 'exit-status', "\x00"*4)
        session.SSHSession.loseConnection(self)

    def channelClosed(self):
        log.msg("Called channelClosed in SSHSession")


class CowrieUser(avatar.ConchUser):
    """
    """
    implements(conchinterfaces.IConchUser)

    def __init__(self, username, server):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.server = server
        self.cfg = self.server.cfg

        self.channelLookup.update(
            {"session": HoneyPotSSHSession,
             "direct-tcpip": CowrieOpenConnectForwardingClient})

        self.uid = self.gid = auth.UserDB(self.cfg).getUID(self.username)
        if not self.uid:
            self.home = '/root'
        else:
            self.home = '/home/' + username

        # sftp support enabled only when option is explicitly set
        if self.cfg.has_option('honeypot', 'sftp_enabled'):
            if (self.cfg.get('honeypot', 'sftp_enabled') == "true"):
                self.subsystemLookup['sftp'] = filetransfer.FileTransferServer

    def logout(self):
        log.msg(
            'avatar %s logging out'
            % (self.username,))


class SSHSessionForCowrieUser:
    """
    """
    implements(conchinterfaces.ISession)

    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrwieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """
        self.protocol = None
        self.environ = {'PATH': '/bin:/usr/bin:/usr/local/bin'}
        self.avatar = avatar
        self.server = avatar.server
        self.cfg = avatar.cfg
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username

    def openShell(self, proto):
        self.protocol = protocol.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, self)
        self.protocol.makeConnection(proto)
        proto.makeConnection(session.wrapProtocol(self.protocol))

    def getPty(self, terminal, windowSize, attrs):
        log.msg(eventid='KIPP0010', width=windowSize[0], height=windowSize[1],
            format='Terminal Size: %(width)s %(height)s')
        self.windowSize = windowSize
        return None

    def execCommand(self, proto, cmd):
        self.protocol = protocol.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd)
        self.protocol.makeConnection(proto)
        proto.makeConnection(session.wrapProtocol(self.protocol))

    # this is reliably called on both logout and disconnect
    # we notify the protocol here we lost the connection
    def closed(self):
        if self.protocol:
            self.protocol.connectionLost("disconnected")
            self.protocol = None

    def eofReceived(self):
        if self.protocol:
            self.protocol.eofReceived()

    def windowChanged(self, windowSize):
        self.windowSize = windowSize


def getRSAKeys(cfg):
    public_key = cfg.get('honeypot', 'rsa_public_key')
    private_key = cfg.get('honeypot', 'rsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        log.msg("Generating new RSA keypair...")
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = keys.Key(rsaKey).toString('openssh')
        with open(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with open(private_key, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with open(public_key, 'r') as f:
            publicKeyString = f.read()
        with open(private_key, 'r') as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString


def getDSAKeys(cfg):
    public_key = cfg.get('honeypot', 'dsa_public_key')
    private_key = cfg.get('honeypot', 'dsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        log.msg("Generating new DSA keypair...")
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = keys.Key(dsaKey).toString('openssh')
        with open(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with open(private_key, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with open(public_key, 'r') as f:
            publicKeyString = f.read()
        with open(private_key, 'r') as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString


class CowrieSFTPFile:
    """
    """
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
        if "permissions" in attrs:
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
        if (self.bytes_written > 0):
            self.server.fs.update_size(self.filename, self.bytes_written)
        return self.server.fs.close(self.fd)

    def readChunk(self, offset, length):
        return self.contents[offset:offset+length]

    def writeChunk(self, offset, data):
        self.server.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.server.fs.write(self.fd, data)
        self.bytes_written += len(data)

    def getAttrs(self):
        s = self.server.fs.stat(self.filename)
        return self.server._getAttrs(s)

    def setAttrs(self, attrs):
        raise NotImplementedError


class CowrieSFTPDirectory:
    """
    """
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


class SFTPServerForCowrieUser:
    """
    """
    implements(conchinterfaces.ISFTPServer)

    def __init__(self, avatar):
        self.avatar = avatar
        self.fs = self.avatar.server.fs

    def _absPath(self, path):
        home = self.avatar.home
        return os.path.abspath(os.path.join(home, path))

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
            "mtime": int(s.st_mtime)
        }

    def gotVersion(self, otherVersion, extData):
        return {}

    def openFile(self, filename, flags, attrs):
        log.msg("SFTP openFile: %s" % filename)
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)

    def removeFile(self, filename):
        log.msg("SFTP removeFile: %s" % filename)
        return self.fs.remove(self._absPath(filename))

    def renameFile(self, oldpath, newpath):
        log.msg("SFTP renameFile: %s %s" % (oldpath, newpath))
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    def makeDirectory(self, path, attrs):
        log.msg("SFTP makeDirectory: %s" % path)
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)
        return

    def removeDirectory(self, path):
        log.msg("SFTP removeDirectory: %s" % path)
        return self.fs.rmdir(self._absPath(path))

    def openDirectory(self, path):
        log.msg("SFTP OpenDirectory: %s" % path)
        return CowrieSFTPDirectory(self, self._absPath(path))

    def getAttrs(self, path, followLinks):
        log.msg("SFTP getAttrs: %s" % path)
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)

    def setAttrs(self, path, attrs):
        log.msg("SFTP setAttrs: %s" % path)
        path = self._absPath(path)
        return self._setAttrs(path, attrs)

    def readLink(self, path):
        log.msg("SFTP readLink: %s" % path)
        path = self._absPath(path)
        return self.fs.readlink(path)

    def makeLink(self, linkPath, targetPath):
        log.msg("SFTP makeLink: %s" % path)
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)

    def realPath(self, path):
        log.msg("SFTP realPath: %s" % path)
        return self.fs.realpath(self._absPath(path))

    def extendedRequest(self, extName, extData):
        raise NotImplementedError

components.registerAdapter(SFTPServerForCowrieUser, CowrieUser, conchinterfaces.ISFTPServer)
components.registerAdapter(SSHSessionForCowrieUser, CowrieUser, session.ISession)


def CowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg(eventid='KIPP0014', format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s',
            dst_ip=remoteHP[0], dst_port=remoteHP[1])
    return CowrieConnectForwardingChannel(remoteHP,
       remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket,
       avatar=avatar)


class CowrieConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    """
    def channelOpen(self, specificData):
        pass

    def dataReceived(self, data):
        log.msg(eventid='KIPP0015', format='direct-tcp forward to %(dst_ip)s:%(dst_port)s with data %(data)s',
            dst_ip=self.hostport[0], dst_port=self.hostport[1], data=repr(data))
        self._close("Connection refused")

# vim: set et sw=4 et:
