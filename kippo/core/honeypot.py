# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.cred import portal, checkers, credentials, error
from twisted.conch import avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, common, transport
from twisted.conch.insults import insults
from twisted.application import service, internet
from twisted.protocols.policies import TrafficLoggingFactory
from twisted.internet import reactor, protocol, defer
from twisted.python import failure, log
from zope.interface import implements
from copy import deepcopy, copy
import sys, os, random, pickle, time, stat, shlex

from kippo.core import ttylog, fs
from kippo.core.config import config
import commands

class HoneyPotCommand(object):
    def __init__(self, honeypot, *args):
        self.honeypot = honeypot
        self.args = args
        self.writeln = self.honeypot.writeln
        self.write = self.honeypot.terminal.write
        self.nextLine = self.honeypot.terminal.nextLine
        self.fs = self.honeypot.fs

    def start(self):
        self.call()
        self.exit()

    def call(self):
        self.honeypot.writeln('Hello World! [%s]' % repr(self.args))

    def exit(self):
        self.honeypot.cmdstack.pop()
        self.honeypot.cmdstack[-1].resume()

    def ctrl_c(self):
        print 'Received CTRL-C, exiting..'
        self.writeln('^C')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT: %s' % line

    def resume(self):
        pass

class HoneyPotShell(object):
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.showPrompt()
        self.cmdpending = []

    def lineReceived(self, line):
        print 'CMD: %s' % line
        for i in [x.strip() for x in line.strip().split(';')]:
            if not len(i):
                continue
            self.cmdpending.append(i)
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()

    def runCommand(self):
        if not len(self.cmdpending):
            self.showPrompt()
            return
        i = self.cmdpending.pop(0)
        try:
            cmdAndArgs = shlex.split(i)
        except:
            self.honeypot.writeln(
                '-bash: syntax error: unexpected end of file')
            # could run runCommand here, but i'll just clear the list instead
            self.cmdpending = []
            self.showPrompt()
            return
        cmd, args = cmdAndArgs[0], []
        if len(cmdAndArgs) > 1:
            args = cmdAndArgs[1:]
        rargs = []
        for arg in args:
            matches = self.honeypot.fs.resolve_path_wc(arg, self.honeypot.cwd)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.honeypot.getCommand(cmd)
        if cmdclass:
            obj = cmdclass(self.honeypot, *rargs)
            self.honeypot.cmdstack.append(obj)
            self.honeypot.setTypeoverMode()
            obj.start()
        else:
            if len(i):
                self.honeypot.writeln('bash: %s: command not found' % cmd)
                if len(self.cmdpending):
                    self.runCommand()
                else:
                    self.showPrompt()

    def resume(self):
        self.honeypot.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        prompt = '%s:%%(path)s# ' % self.honeypot.hostname
        path = self.honeypot.cwd
        if path == '/root':
            path = '~'
        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

    def ctrl_c(self):
        self.honeypot.lineBuffer = []
        self.honeypot.lineBufferIndex = 0
        self.honeypot.terminal.nextLine()
        self.showPrompt()

class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, env):
        self.user = user
        self.env = env
        self.cwd = '/root'
        self.hostname = self.env.cfg.get('honeypot', 'hostname')
        self.fs = fs.HoneyPotFilesystem(deepcopy(self.env.fs))
        # commands is also a copy so we can add stuff on the fly
        self.commands = copy(self.env.commands)
        self.password_input = False
        self.cmdstack = []

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.cmdstack = [HoneyPotShell(self)]

        # You are in a maze of twisty little passages, all alike
        p = self.terminal.transport.session.conn.transport.transport.getPeer()
        self.clientIP = p[1]
        self.logintime = time.time()

    def connectionLost(self, reason):
        recvline.HistoricRecvLine.connectionLost(self, reason)
        # not sure why i need to do this:
        del self.fs
        del self.commands

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def getCommand(self, cmd):
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
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
        if path in self.commands:
            return self.commands[path]
        return None

    def lineReceived(self, line):
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def keystrokeReceived(self, keyID, modifier):
        if type(keyID) == type(''):
            ttylog.ttylog_write(self.terminal.ttylog_file, len(keyID),
                ttylog.DIR_READ, time.time(), keyID)
        if keyID == '\x03':
            self.cmdstack[-1].ctrl_c()
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

    def handle_RETURN(self):
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)

class LoggingServerProtocol(insults.ServerProtocol):
    def connectionMade(self):
        self.ttylog_file = '%s/tty/%s-%s.log' % \
            (config().get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'),
            int(random.random() * 10000))
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
        insults.ServerProtocol.connectionLost(self, reason)

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
        self.cfg = config()
        self.commands = {}
        import kippo.commands
        for c in kippo.commands.__all__:
            module = __import__('kippo.commands.%s' % c,
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)
        self.fs = pickle.load(file(
            self.cfg.get('honeypot', 'filesystem_file')))

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
        # FIXME: try to mimic something real 100%
        t = transport.SSHServerTransport()
        t.ourVersionString = 'SSH-2.0-OpenSSH_5.1p1 Debian-5'
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        t.factory = self
        return t

class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, users):
        self.users = users

    def requestAvatarId(self, credentials):
        if (credentials.username, credentials.password) in self.users:
            print 'login attempt [%s/%s] succeeded' % \
                (credentials.username, credentials.password)
            return defer.succeed(credentials.username)
        else:
            print 'login attempt [%s/%s] failed' % \
                (credentials.username, credentials.password)
            return defer.fail(error.UnauthorizedLogin())

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
        file(cfg.get('honeypot', 'public_key'), 'w+b').write(publicKeyString)
        file(cfg.get('honeypot', 'private_key'), 'w+b').write(privateKeyString)
        print "done."
    else:
        cfg = config()
        publicKeyString = file(cfg.get('honeypot', 'public_key')).read()
        privateKeyString = file(cfg.get('honeypot', 'private_key')).read()
    return publicKeyString, privateKeyString

# vim: set sw=4 et:
