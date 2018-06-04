
"""
Output plugin for HPFeeds

"""

from __future__ import division, absolute_import

import os
import struct
import hashlib
import json
import socket
import uuid

from twisted.python import log

import cowrie.core.output

from cowrie.core.config import CONFIG

try:
    buffer         # Python 2
except NameError:  # Python 3
    buffer = memoryview

"""
From https://github.com/threatstream/kippo/blob/master/kippo/dblog/hpfeeds.py
"""

BUFSIZ = 16384

OP_ERROR        = 0
OP_INFO         = 1
OP_AUTH         = 2
OP_PUBLISH      = 3
OP_SUBSCRIBE    = 4

MAXBUF = 1024**2
SIZES = {
    OP_ERROR: 5+MAXBUF,
    OP_INFO: 5+256+20,
    OP_AUTH: 5+256+20,
    OP_PUBLISH: 5+MAXBUF,
    OP_SUBSCRIBE: 5+256*2,
}

COWRIECHAN = 'cowrie.sessions'


class BadClient(Exception):
    pass


def set2json(value):
    if isinstance(value, set):
        return list(value)
    return value


def strpack8(x):
    """
    # packs a string with 1 byte length field
    """
    if isinstance(x, str): x = x.encode('latin1')
    return struct.pack('!B', len(x)) + x



# unpacks a string with 1 byte length field
def strunpack8(x):
    l = x[0]
    return x[1:1+l], x[1+l:]



def msghdr(op, data):
    return struct.pack('!iB', 5+len(data), op) + data



def msgpublish(ident, chan, data):
    return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)



def msgsubscribe(ident, chan):
    if isinstance(chan, str): chan = chan.encode('latin1')
    return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)



def msgauth(rand, ident, secret):
    hash = hashlib.sha1(bytes(rand)+secret).digest()
    return msghdr(OP_AUTH, strpack8(ident) + hash)



class FeedUnpack(object):
    def __init__(self):
        self.buf = bytearray()


    def __iter__(self):
        return self


    def next(self):
        return self.unpack()


    def feed(self, data):
        self.buf.extend(data)


    def unpack(self):
        if len(self.buf) < 5:
            raise StopIteration('No message.')

        ml, opcode = struct.unpack('!iB', buffer(self.buf, 0, 5))
        if ml > SIZES.get(opcode, MAXBUF):
            raise BadClient('Not respecting MAXBUF.')

        if len(self.buf) < ml:
            raise StopIteration('No message.')

        data = bytearray(buffer(self.buf, 5, ml-5))
        del self.buf[:ml]
        return opcode, data



class hpclient(object):
    def __init__(self, server, port, ident, secret, debug):
        log.msg('hpfeeds client init broker {0}:{1}, identifier {2}'.format(server, port, ident))
        self.server, self.port = server, int(port)
        self.ident, self.secret = ident.encode('latin1'), secret.encode('latin1')
        self.debug = debug
        self.unpacker = FeedUnpack()
        self.state = 'INIT'

        self.connect()
        self.sendfiles = []
        self.filehandle = None


    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(3)
        try: self.s.connect((self.server, self.port))
        except:
            log.msg('hpfeeds client could not connect to broker.')
            self.s = None
        else:
            self.s.settimeout(None)
            self.handle_established()


    def send(self, data):
        if not self.s:
            self.connect()

        if not self.s: return
        self.s.send(data)


    def close(self):
        self.s.close()
        self.s = None


    def handle_established(self):
        if self.debug:
            log.msg('hpclient established')
        while self.state != 'GOTINFO':
            self.read()

        # Quickly try to see if there was an error message
        self.s.settimeout(0.5)
        self.read()
        self.s.settimeout(None)


    def read(self):
        if not self.s: return
        try: d = self.s.recv(BUFSIZ)
        except socket.timeout:
            return

        if not d:
            if self.debug: log.msg('hpclient connection closed?')
            self.close()
            return

        self.unpacker.feed(d)
        try:
            for opcode, data in self.unpacker:
                if self.debug: log.msg('hpclient msg opcode {0:x} data {1}'.format(opcode,
                    ''.join('{:02x}'.format(x) for x in data)))
                if opcode == OP_INFO:
                    name, rand = strunpack8(data)
                    if self.debug: log.msg('hpclient server name {0} rand {1}'.format(name,
                    ''.join('{:02x}'.format(x) for x in rand)))
                    self.send(msgauth(rand, self.ident, self.secret))
                    self.state = 'GOTINFO'

                elif opcode == OP_PUBLISH:
                    ident, data = strunpack8(data)
                    chan, data = strunpack8(data)
                    if self.debug:
                        log.msg('publish to {0} by {1}: {2}'.format(chan, ident,
                                 ''.join('{:02x}'.format(x) for x in data)))
                elif opcode == OP_ERROR:
                    log.err('errormessage from server: {0}'.format(
                                 ''.join('{:02x}'.format(x) for x in data)))
                else:
                    log.err('unknown opcode message: {0:x}'.format(opcode))
        except BadClient:
            log.err('unpacker error, disconnecting.')
            self.close()


    def publish(self, channel, **kwargs):
        try:
            self.send(msgpublish(self.ident, channel, json.dumps(kwargs, default=set2json).encode('latin1')))
        except Exception as e:
            log.err('connection to hpfriends lost: {0}'.format(e))
            log.err('connecting')
            self.connect()
            self.send(msgpublish(self.ident, channel, json.dumps(kwargs, default=set2json).encode('latin1')))


    def sendfile(self, filepath):
        # does not read complete binary into memory, read and send chunks
        if not self.filehandle:
            self.sendfileheader(i.file)
            self.sendfiledata()
        else: self.sendfiles.append(filepath)


    def sendfileheader(self, filepath):
        self.filehandle = open(filepath, 'rb')
        fsize = os.stat(filepath).st_size
        headc = strpack8(self.ident) + strpack8(UNIQUECHAN)
        headh = struct.pack('!iB', 5+len(headc)+fsize, OP_PUBLISH)
        self.send(headh + headc)


    def sendfiledata(self):
        tmp = self.filehandle.read(BUFSIZ)
        if not tmp:
            if self.sendfiles:
                fp = self.sendfiles.pop(0)
                self.sendfileheader(fp)
            else:
                self.filehandle = None
                self.handle_io_in(b'')
        else:
            self.send(tmp)



class Output(cowrie.core.output.Output):
    """
    Output plugin for HPFeeds
    """

    def __init__(self):
        log.msg("Early version of hpfeeds-output, untested!")
        cowrie.core.output.Output.__init__(self)


    def start(self):
        """
        """
        server = CONFIG.get('output_hpfeeds', 'server')
        port = CONFIG.getint('output_hpfeeds', 'port')
        ident = CONFIG.get('output_hpfeeds', 'identifier')
        secret = CONFIG.get('output_hpfeeds', 'secret')
        debug = CONFIG.getboolean('output_hpfeeds', 'debug')
        self.client = hpclient(server, port, ident, secret, debug)
        self.meta = {}


    def stop(self):
        """
        """
        pass


    def write(self, entry):
        """
        """
        session = entry["session"]
        if entry["eventid"] == 'cowrie.session.connect':
            self.meta[session] = {'session':session,
                'startTime': entry["timestamp"], 'endTime':'',
                'peerIP': entry["src_ip"], 'peerPort': entry["src_port"],
                'hostIP': entry["dst_ip"], 'hostPort': entry["dst_port"],
                'loggedin': None, 'credentials':[], 'commands':[],
                'unknownCommands':[], 'urls':[], 'version': None,
                'ttylog': None, 'hashes': set(), 'protocol': entry['protocol']}

        elif entry["eventid"] == 'cowrie.login.success':
            u, p = entry['username'], entry['password']
            self.meta[session]['loggedin'] = (u, p)

        elif entry["eventid"] == 'cowrie.login.failed':
            u, p = entry['username'], entry['password']
            self.meta[session]['credentials'].append((u, p))

        elif entry["eventid"] == 'cowrie.command.input':
            c = entry['input']
            self.meta[session]['commands'].append(c)

        elif entry["eventid"] == 'cowrie.command.failed':
            uc = entry['input']
            self.meta[session]['unknownCommands'].append(uc)

        elif entry["eventid"] == 'cowrie.session.file_download':
            url = entry['url']
            self.meta[session]['urls'].append(url)
            self.meta[session]['hashes'].add(entry['shasum'])

        elif entry["eventid"] == 'cowrie.session.file_upload':
            self.meta[session]['hashes'].add(entry['shasum'])

        elif entry["eventid"] == 'cowrie.client.version':
            v = entry['version']
            self.meta[session]['version'] = v

        elif entry["eventid"] == 'cowrie.log.closed':
            # entry["ttylog"]
            with open(entry["ttylog"]) as ttylog:
                self.meta[session]['ttylog'] = ttylog.read().encode('hex')

        elif entry["eventid"] == 'cowrie.session.closed':
            log.msg('publishing metadata to hpfeeds')
            meta = self.meta[session]
            self.meta[session]['endTime'] = entry["timestamp"]
            self.client.publish(COWRIECHAN, **meta)
