from twisted.cred import portal, checkers, credentials
from twisted.conch import error, avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, common, transport
from twisted.conch.insults import insults
from twisted.application import service, internet
from twisted.protocols.policies import TrafficLoggingFactory
from twisted.internet import reactor, protocol
from twisted.python import log
from zope.interface import implements
from copy import deepcopy
import sys, os, random, pickle, time, stat, copy

from core import ttylog
from core.fstypes import *
import config

class HoneyPotCommand(object):
    def __init__(self, honeypot, args):
        self.honeypot = honeypot
        self.args = args

    def start(self):
        self.call(self.args)
        self.exit()

    def call(self, *args):
        self.honeypot.writeln('Hello World! [%s]' % repr(args))

    def exit(self):
        self.honeypot.cmdstack.pop()
        self.honeypot.cmdstack[-1].resume()

    def lineReceived(self, line):
        print 'INPUT: %s' % line

    def resume(self):
        pass

class HoneyPotShell(object):
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.showPrompt()

    def lineReceived(self, line):
        print 'CMD: %s' % line
        cmdAndArgs = line.split(' ', 1)
        if len(cmdAndArgs) > 1:
            cmd, args = cmdAndArgs
        else:
            cmd, args = cmdAndArgs[0], ''
        cmdclass = self.honeypot.getCommand(cmd)
        if cmdclass:
            obj = cmdclass(self.honeypot, args)
            self.honeypot.cmdstack.append(obj)
            obj.start()
        else:
            self.honeypot.writeln('bash: %s: command not found' % cmd)
            self.showPrompt()

    def resume(self):
        self.showPrompt()

    def showPrompt(self):
        prompt = '%s:%%(path)s# ' % self.honeypot.hostname
        path = self.honeypot.cwd
        if path == '/root':
            path = '~'
        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, env):
        self.user = user
        self.env = env
        self.cwd = '/root'
        self.hostname = config.fake_hostname
        self.fs = HoneyPotFilesystem(deepcopy(self.env.fs))
        self.password_input = False
        self.cmdstack = []

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.cmdstack = [HoneyPotShell(self)]

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def getCommand(self, cmd):
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.env.commands:
            return self.env.commands[cmd]
        if cmd[0] in ('.', '/'):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in ['%s/%s' % (x, cmd) for x in \
                    '/bin', '/usr/bin', '/sbin', '/usr/sbin']:
                if self.fs.exists(i):
                    path = i
                    break
        if path in self.env.commands:
            return self.env.commands[path]
        return None

    def lineReceived(self, line):
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def keystrokeReceived(self, keyID, modifier):
        if type(keyID) == type(''):
            ttylog.ttylog_write(self.terminal.ttylog_file, len(keyID),
                ttylog.DIR_READ, time.time(), keyID)
        recvline.HistoricRecvLine.keystrokeReceived(self, keyID, modifier)

    # Easier way to implement password input?
    def characterReceived(self, ch, moreCharactersComing):
        if self.mode == 'insert':
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex:self.lineBufferIndex+1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input: 
            self.terminal.write(ch)

    def writeln(self, data):
        self.terminal.write(data)
        self.terminal.nextLine()

class LoggingServerProtocol(insults.ServerProtocol):
    def connectionMade(self):
        self.ttylog_file = './log/tty/%s-%s.log' % \
            (time.strftime('%Y%m%d-%H%M%S'), int(random.random() * 10000))
        print 'Opening TTY log: %s' % self.ttylog_file
        ttylog.ttylog_open(self.ttylog_file, time.time())
        self.ttylog_open = True
        insults.ServerProtocol.connectionMade(self)

    def write(self, bytes):
        if self.ttylog_open:
            ttylog.ttylog_write(self.ttylog_file, len(bytes),
                ttylog.DIR_WRITE, time.time(), bytes)
        insults.ServerProtocol.write(self, bytes)

    def connectionLost(self, reason):
        if self.ttylog_open:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False

class HoneyPotAvatar(avatar.ConchUser):
    implements(conchinterfaces.ISession)

    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.channelLookup.update({'session':session.SSHSession})

    def openShell(self, protocol):
        serverProtocol = LoggingServerProtocol(HoneyPotProtocol, self, self.env)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        self.windowSize = windowSize
        return None

    def execCommand(self, protocol, cmd):
        raise NotImplementedError

    def closed(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize

class HoneyPotEnvironment(object):
    def __init__(self):
        from core.cmdl import cmdl
        self.commands = cmdl

        print 'Loading filesystem...',
        sys.stdout.flush()
        self.fs = pickle.load(file('fs.pickle'))
        print 'done'

class HoneyPotFilesystem(object):
    def __init__(self, fs):
        self.fs = fs

    def resolve_path(self, path, cwd):
        pieces = path.rstrip('/').split('/')

        if path[0] == '/':
            cwd = []
        else:
            cwd = [x for x in cwd.split('/') if len(x) and x is not None]

        while 1:
            if not len(pieces):
                break
            piece = pieces.pop(0)
            if piece == '..':
                if len(cwd): cwd.pop()
                continue
            if piece in ('.', ''):
                continue
            cwd.append(piece)

        return '/%s' % '/'.join(cwd)

    def get_path(self, path):
        p = self.fs
        for i in path.split('/'):
            if not i:
                continue
            p = [x for x in p[A_CONTENTS] if x[A_NAME] == i][0]
        return p[A_CONTENTS]

    def list_files(self, path):
        return self.get_path(path)

    def exists(self, path):
        pieces = path.strip('/').split('/')
        p = self.fs
        while 1:
            if not len(pieces):
                break
            piece = pieces.pop(0)
            if piece not in [x[A_NAME] for x in p[A_CONTENTS]]:
                return False
            p = [x for x in p[A_CONTENTS] \
                if x[A_NAME] == piece][0]
        return True

class HoneyPotRealm:
    implements(portal.IRealm)

    def __init__(self):
        # I don't know if i'm supposed to keep static stuff here
        self.env = HoneyPotEnvironment()

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception, "No supported interfaces found."

# As implemented by Kojoney
class HoneyPotSSHFactory(factory.SSHFactory):
    #publicKeys = {'ssh-rsa': keys.getPublicKeyString(data=publicKey)}
    #privateKeys = {'ssh-rsa': keys.getPrivateKeyObject(data=privateKey)}
    services = {
        'ssh-userauth': userauth.SSHUserAuthServer,
        'ssh-connection': connection.SSHConnection,
        }

    def buildProtocol(self, addr):
        t = transport.SSHServerTransport()
        #
        # Fix for BUG 1463701 "NMap recognizes Kojoney as a Honeypot"
        #
        t.ourVersionString = 'SSH-2.0-OpenSSH_5.1p1 Debian-5'
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        t.factory = self
        return t

def getRSAKeys():
    if not (os.path.exists('public.key') and os.path.exists('private.key')):
        # generate a RSA keypair
        print "Generating RSA keypair..."
        from Crypto.PublicKey import RSA
        KEY_LENGTH = 1024
        rsaKey = RSA.generate(KEY_LENGTH, common.entropy.get_bytes)
        publicKeyString = keys.makePublicKeyString(rsaKey)
        privateKeyString = keys.makePrivateKeyString(rsaKey)
        # save keys for next time
        file('public.key', 'w+b').write(publicKeyString)
        file('private.key', 'w+b').write(privateKeyString)
        print "done."
    else:
        publicKeyString = file('public.key').read()
        privateKeyString = file('private.key').read()
    return publicKeyString, privateKeyString
