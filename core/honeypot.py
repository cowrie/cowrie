# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.cred import portal, checkers, credentials
from twisted.conch import error, avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, common, transport
from twisted.conch.insults import insults
from twisted.application import service, internet
from twisted.protocols.policies import TrafficLoggingFactory
from twisted.internet import reactor, protocol
from twisted.python import log
from zope.interface import implements
from copy import deepcopy, copy
import sys, os, random, pickle, time, stat, shlex

from core import ttylog
from core.fstypes import *
import commands, config

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

    def lineReceived(self, line):
        print 'CMD: %s' % line
        if not len(line.strip()):
            self.showPrompt()
            return
        try:
            cmdAndArgs = shlex.split(line.strip())
        except:
            self.honeypot.writeln(
                '-bash: syntax error: unexpected end of file')
            self.showPrompt()
            return
        cmd, args = cmdAndArgs[0], []
        if len(cmdAndArgs) > 1:
            args = cmdAndArgs[1:]
        cmdclass = self.honeypot.getCommand(cmd)
        if cmdclass:
            obj = cmdclass(self.honeypot, *args)
            self.honeypot.cmdstack.append(obj)
            self.honeypot.setTypeoverMode()
            obj.start()
        else:
            if len(line.strip()):
                self.honeypot.writeln('bash: %s: command not found' % cmd)
            self.showPrompt()

    def resume(self):
        self.honeypot.setInsertMode()
        self.showPrompt()

    def showPrompt(self):
        prompt = '%s:%%(path)s# ' % self.honeypot.hostname
        path = self.honeypot.cwd
        if path == '/root':
            path = '~'
        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

    def ctrl_c(self):
        self.honeypot.terminal.nextLine()
        self.showPrompt()

class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, env):
        self.user = user
        self.env = env
        self.cwd = '/root'
        self.hostname = config.fake_hostname
        self.fs = HoneyPotFilesystem(deepcopy(self.env.fs))
        # commands is also a copy so we can add stuff on the fly
        self.commands = copy(self.env.commands)
        self.password_input = False
        self.cmdstack = []

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.cmdstack = [HoneyPotShell(self)]

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

class LoggingServerProtocol(insults.ServerProtocol):
    def connectionMade(self):
        self.ttylog_file = '%s/tty/%s-%s.log' % \
            (config.log_path, time.strftime('%Y%m%d-%H%M%S'),
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
        self.commands = {}
        import commands
        for c in commands.__all__:
            module = __import__('commands.%s' % c,
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)
        self.fs = pickle.load(file('fs.pickle'))

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
        f = self.getfile(path)
        if f is not False:
            return True

    def update_realfile(self, f, realfile):
        if not f[A_REALFILE] and os.path.exists(realfile) and \
                not os.path.islink(realfile) and os.path.isfile(realfile) and \
                f[A_SIZE] < 25000000:
            print 'Updating realfile to %s' % realfile
            f[A_REALFILE] = realfile

    def realfile(self, f, path):
        self.update_realfile(f, path)
        if f[A_REALFILE]:
            return f[A_REALFILE]
        return None

    def getfile(self, path):
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
        return p

    def mkfile(self, path, uid, gid, size, mode, ctime = None):
        if ctime is None:
            ctime = time.time()
        dir = self.get_path(os.path.dirname(path))
        outfile = os.path.basename(path)
        if outfile in [x[A_NAME] for x in dir]:
            dir.remove([x for x in dir if x[A_NAME] == outfile][0])
        dir.append([outfile, T_FILE, uid, gid, size, mode, ctime, [],
            None, None])
        return True

    def mkdir(self, path, uid, gid, size, mode, ctime = None):
        if ctime is None:
            ctime = time.time()
        if not len(path.strip('/')):
            return False
        try:
            dir = self.get_path(os.path.dirname(path.strip('/')))
        except IndexError:
            return False
        dir.append([os.path.basename(path), T_DIR, uid, gid, size, mode,
            ctime, [], None, None])
        return True

    def is_dir(self, path):
        if path == '/':
            return True
        dir = self.get_path(os.path.dirname(path))
        l = [x for x in dir
            if x[A_NAME] == os.path.basename(path) and
            x[A_TYPE] == T_DIR]
        if l:
            return True
        return False

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

# vim: set sw=4 et:
