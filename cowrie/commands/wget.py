# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import time
import urlparse
import re
import exceptions
import os
import getopt
import hashlib

from twisted.web import client
from twisted.internet import reactor, ssl
from twisted.python import log

from OpenSSL import SSL

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

def tdiff(seconds):
    t = seconds
    days = int(t / (24 * 60 * 60))
    t -= (days * 24 * 60 * 60)
    hours = int(t / (60 * 60))
    t -= (hours * 60 * 60)
    minutes = int(t / 60)
    t -= (minutes * 60)

    s = '%ds' % int(t)
    if minutes >= 1: s = '%dm %s' % (minutes, s)
    if hours >= 1: s = '%dh %s' % (hours, s)
    if days >= 1: s = '%dd %s' % (days, s)
    return s

def sizeof_fmt(num):
    for x in ['bytes','K','M','G','T']:
        if num < 1024.0:
            return "%d%s" % (num, x)
        num /= 1024.0

# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands( s, sep=','):
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

class command_wget(HoneyPotCommand):
    def start(self):
        try:
            optlist, args = getopt.getopt(self.args, 'cqO:')
        except getopt.GetoptError as err:
            self.write('Unrecognized option\n')
            self.exit()
            return

        if len(args):
            url = args[0].strip()
        else:
            self.write('wget: missing URL\n')
            self.write('Usage: wget [OPTION]... [URL]...\n\n')
            self.write('Try `wget --help\' for more options.\n')
            self.exit()
            return

        outfile = None
        self.quiet = False
        for opt in optlist:
            if opt[0] == '-O':
                outfile = opt[1]
            if opt[0] == '-q':
                self.quiet = True

        if '://' not in url:
            url = 'http://%s' % url

        urldata = urlparse.urlparse(url)

        if outfile is None:
            outfile = urldata.path.split('/')[-1]
            if not len(outfile.strip()) or not urldata.path.count('/'):
                outfile = 'index.html'

        outfile = self.fs.resolve_path(outfile, self.protocol.cwd)
        path = os.path.dirname(outfile)
        if not path or \
                not self.fs.exists(path) or \
                not self.fs.isdir(path):
            self.write('wget: %s: Cannot open: No such file or directory\n' % \
                outfile)
            self.exit()
            return

        self.url = url
        self.limit_size = 0
        cfg = self.protocol.cfg
        if cfg.has_option('honeypot', 'download_limit_size'):
            self.limit_size = int(cfg.get('honeypot', 'download_limit_size'))

        self.download_path = cfg.get('honeypot', 'download_path')

        self.safeoutfile = '%s/%s_%s' % \
            (self.download_path,
            time.strftime('%Y%m%d%H%M%S'),
            re.sub('[^A-Za-z0-9]', '_', url))
        self.deferred = self.download(url, outfile, self.safeoutfile)
        if self.deferred:
            self.deferred.addCallback(self.success, outfile)
            self.deferred.addErrback(self.error, url)

    def download(self, url, fakeoutfile, outputfile, *args, **kwargs):
        try:
            parsed = urlparse.urlparse(url)
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == 'https' else 80)
            path = parsed.path or '/'
            if scheme != 'http' and scheme != 'https':
                raise exceptions.NotImplementedError
        except:
            self.write('%s: Unsupported scheme.\n' % (url,))
            self.exit()
            return None

        if self.quiet == False:
            self.write('--%s--  %s' % (time.strftime('%Y-%m-%d %H:%M:%S\n'), url))
            self.write('Connecting to %s:%d... connected.\n' % (host, port))
            self.write('HTTP request sent, awaiting response... ')

        factory = HTTPProgressDownloader(
            self, fakeoutfile, url, outputfile, *args, **kwargs)
        out_addr = None
        if self.protocol.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.protocol.cfg.get('honeypot', 'out_addr'), 0)

        if scheme == 'https':
            contextFactory = ssl.ClientContextFactory()
            contextFactory.method = SSL.SSLv23_METHOD
            reactor.connectSSL(host, port, factory, contextFactory)
        else: #can only be http, since we raised an error above for unknown schemes
            self.connection = reactor.connectTCP(
                host, port, factory, bindAddress=out_addr)

        return factory.deferred

    def handle_CTRL_C(self):
        self.write('^C\n')
        self.connection.transport.loseConnection()

    def success(self, data, outfile):
        if not os.path.isfile(self.safeoutfile):
            log.msg("there's no file " + self.safeoutfile)
            self.exit()

        shasum = hashlib.sha256(open(self.safeoutfile, 'rb').read()).hexdigest()
        hash_path = '%s/%s' % (self.download_path, shasum)

        # if we have content already, delete temp file
        if not os.path.exists(hash_path):
            os.rename(self.safeoutfile, hash_path)
        else:
            os.remove(self.safeoutfile)
            log.msg("Not storing duplicate content " + shasum)

        self.protocol.logDispatch(eventid='cowrie.session.file_download',
            format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
            url=self.url,
            outfile=hash_path,
            shasum=shasum )

        log.msg(eventid='cowrie.session.file_download',
                format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                url=self.url,
                outfile=hash_path,
                shasum=shasum)

        # link friendly name to hash
        os.symlink( shasum, self.safeoutfile )

        # FIXME: is this necessary?
        self.safeoutfile = hash_path

        # update the honeyfs to point to downloaded file
        f = self.fs.getfile(outfile)
        f[A_REALFILE] = hash_path
        self.exit()

    def error(self, error, url):
        if hasattr(error, 'getErrorMessage'): # exceptions
            error = error.getErrorMessage()
        self.write(error+'\n')
        # Real wget also adds this:
        #self.write('%s ERROR 404: Not Found.\n' % \
        #    time.strftime('%Y-%m-%d %T'))
        self.exit()
commands['/usr/bin/wget'] = command_wget
commands['/usr/bin/dget'] = command_wget

# from http://code.activestate.com/recipes/525493/
class HTTPProgressDownloader(client.HTTPDownloader):
    def __init__(self, wget, fakeoutfile, url, outfile, headers=None):
        client.HTTPDownloader.__init__(self, url, outfile, headers=headers,
            agent='Wget/1.11.4')
        self.status = None
        self.wget = wget
        self.fakeoutfile = fakeoutfile
        self.lastupdate = 0
        self.started = time.time()
        self.proglen = 0
        self.nomore = False
        self.quiet = self.wget.quiet

    def noPage(self, reason): # called for non-200 responses
        if self.status == '304':
            client.HTTPDownloader.page(self, '')
        else:
            client.HTTPDownloader.noPage(self, reason)

    def gotHeaders(self, headers):
        if self.status == '200':
            if self.quiet == False:
                self.wget.write('200 OK\n')
            if 'content-length' in headers:
                self.totallength = int(headers['content-length'][0])
            else:
                self.totallength = 0
            if 'content-type' in headers:
                self.contenttype = headers['content-type'][0]
            else:
                self.contenttype = 'text/whatever'
            self.currentlength = 0.0

            if self.totallength > 0:
                if self.quiet == False:
                    self.wget.write('Length: %d (%s) [%s]\n' % \
                        (self.totallength,
                        sizeof_fmt(self.totallength),
                        self.contenttype))
            else:
                if self.quiet == False:
                    self.wget.write('Length: unspecified [%s]\n' % \
                        (self.contenttype))
            if self.wget.limit_size > 0 and \
                    self.totallength > self.wget.limit_size:
                log.msg( 'Not saving URL (%s) due to file size limit' % \
                    (self.wget.url,) )
                self.fileName = os.path.devnull
                self.nomore = True
            if self.quiet == False:
                self.wget.write('Saving to: `%s\n\n' % self.fakeoutfile)

        return client.HTTPDownloader.gotHeaders(self, headers)

    def pagePart(self, data):
        if self.status == '200':
            self.currentlength += len(data)

            # if downloading files of unspecified size, this could happen:
            if not self.nomore and self.wget.limit_size > 0 and \
                    self.currentlength > self.wget.limit_size:
                log.msg( 'File limit reached, not saving any more data!' )
                self.nomore = True
                self.file.close()
                self.fileName = os.path.devnull
                self.file = self.openFile(data)

            if (time.time() - self.lastupdate) < 0.5:
                return client.HTTPDownloader.pagePart(self, data)
            if self.totallength:
                percent = (self.currentlength/self.totallength)*100
                spercent = "%i%%" % percent
            else:
                spercent = '%dK' % (self.currentlength/1000)
                percent = 0
            self.speed = self.currentlength / (time.time() - self.started)
            eta = (self.totallength - self.currentlength) / self.speed
            s = '\r%s [%s] %s %dK/s  eta %s' % \
                (spercent.rjust(3),
                ('%s>' % (int(39.0 / 100.0 * percent) * '=')).ljust(39),
                splitthousands(str(int(self.currentlength))).ljust(12),
                self.speed / 1000,
                tdiff(eta))
            if self.quiet == False:
                self.wget.write(s.ljust(self.proglen))
            self.proglen = len(s)
            self.lastupdate = time.time()
        return client.HTTPDownloader.pagePart(self, data)

    def pageEnd(self):
        if self.totallength != 0 and self.currentlength != self.totallength:
            return client.HTTPDownloader.pageEnd(self)
        if self.quiet == False:
            self.wget.write('\r100%%[%s] %s %dK/s' % \
                ('%s>' % (38 * '='),
                splitthousands(str(int(self.totallength))).ljust(12),
                self.speed / 1000))
            self.wget.write('\n\n')
            self.wget.write(
                '%s (%d KB/s) - `%s\' saved [%d/%d]\n' % \
                (time.strftime('%Y-%m-%d %H:%M:%S'),
                self.speed / 1000,
                self.fakeoutfile, self.currentlength, self.totallength))

        self.wget.fs.mkfile(self.fakeoutfile, 0, 0, self.totallength, 33188)
        self.wget.fs.update_realfile(
            self.wget.fs.getfile(self.fakeoutfile),
            self.wget.safeoutfile)

        self.wget.fileName = self.fileName
        return client.HTTPDownloader.pageEnd(self)

# vim: set sw=4 et:
