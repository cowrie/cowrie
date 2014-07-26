# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from kippo.core.honeypot import HoneyPotCommand
from kippo.core.fs import *
from twisted.web import client
from twisted.internet import reactor

import stat
import time
import urlparse
import random
import re
import exceptions
import os.path
import getopt

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
            optlist, args = getopt.getopt(self.args, 'O:')
        except getopt.GetoptError, err:
            self.writeln('Unrecognized option')
            self.exit()
            return

        if len(args):
            url = args[0].strip()
        else:
            self.writeln('wget: missing URL')
            self.writeln('Usage: wget [OPTION]... [URL]...')
            self.nextLine()
            self.writeln('Try `wget --help\' for more options.')
            self.exit()
            return

        outfile = None
        for opt in optlist:
            if opt[0] == '-O':
                outfile = opt[1]

        if '://' not in url:
            url = 'http://%s' % url

        urldata = urlparse.urlparse(url)

        if outfile is None:
            outfile = urldata.path.split('/')[-1]
            if not len(outfile.strip()) or not urldata.path.count('/'):
                outfile = 'index.html'

        outfile = self.fs.resolve_path(outfile, self.honeypot.cwd)
        path = os.path.dirname(outfile)
        if not path or \
                not self.fs.exists(path) or \
                not self.fs.is_dir(path):
            self.writeln('wget: %s: Cannot open: No such file or directory' % \
                outfile)
            self.exit()
            return

        self.url = url
        self.limit_size = 0
        cfg = self.honeypot.env.cfg
        if cfg.has_option('honeypot', 'download_limit_size'):
            self.limit_size = int(cfg.get('honeypot', 'download_limit_size'))

        self.safeoutfile = '%s/%s_%s' % \
            (cfg.get('honeypot', 'download_path'),
            time.strftime('%Y%m%d%H%M%S'),
            re.sub('[^A-Za-z0-9]', '_', url))
        self.deferred = self.download(url, outfile, self.safeoutfile)
        if self.deferred:
            self.deferred.addCallback(self.success)
            self.deferred.addErrback(self.error, url)

    def download(self, url, fakeoutfile, outputfile, *args, **kwargs):
        try:
            parsed = urlparse.urlparse(url)
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == 'https' else 80)
            path = parsed.path or '/'
            if scheme == 'https' or port != 80:
                self.writeln('Sorry, SSL not supported in this release')
                self.exit()
                return None
            elif scheme != 'http':
                raise exceptions.NotImplementedError
        except:
            self.writeln('%s: Unsupported scheme.' % (url,))
            self.exit()
            return None

        self.writeln('--%s--  %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), url))
        self.writeln('Connecting to %s:%d... connected.' % (host, port))
        self.write('HTTP request sent, awaiting response... ')

        factory = HTTPProgressDownloader(
            self, fakeoutfile, url, outputfile, *args, **kwargs)
        out_addr = None
        if self.honeypot.env.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.honeypot.env.cfg.get('honeypot', 'out_addr'), 0)
        self.connection = reactor.connectTCP(
            host, port, factory, bindAddress=out_addr)
        return factory.deferred

    def ctrl_c(self):
        self.writeln('^C')
        self.connection.transport.loseConnection()

    def success(self, data):
        self.exit()

    def error(self, error, url):
        if hasattr(error, 'getErrorMessage'): # exceptions
            error = error.getErrorMessage()
        self.writeln(error)
        # Real wget also adds this:
        #self.writeln('%s ERROR 404: Not Found.' % \
        #    time.strftime('%Y-%m-%d %T'))
        self.exit()
commands['/usr/bin/wget'] = command_wget

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

    def noPage(self, reason): # called for non-200 responses
        if self.status == '304':
            client.HTTPDownloader.page(self, '')
        else:
            client.HTTPDownloader.noPage(self, reason)

    def gotHeaders(self, headers):
        if self.status == '200':
            self.wget.writeln('200 OK')
            if headers.has_key('content-length'):
                self.totallength = int(headers['content-length'][0])
            else:
                self.totallength = 0
            if headers.has_key('content-type'):
                self.contenttype = headers['content-type'][0]
            else:
                self.contenttype = 'text/whatever'
            self.currentlength = 0.0

            if self.totallength > 0:
                self.wget.writeln('Length: %d (%s) [%s]' % \
                    (self.totallength,
                    sizeof_fmt(self.totallength),
                    self.contenttype))
            else:
                self.wget.writeln('Length: unspecified [%s]' % \
                    (self.contenttype))
            if self.wget.limit_size > 0 and \
                    self.totallength > self.wget.limit_size:
                print 'Not saving URL (%s) due to file size limit' % \
                    (self.wget.url,)
                self.fileName = os.path.devnull
                self.nomore = True
            else:
                msg = 'Saving URL (%s) to %s' % (self.wget.url, self.fileName)
                self.wget.honeypot.logDispatch(msg)
                print msg
            self.wget.writeln('Saving to: `%s' % self.fakeoutfile)
            self.wget.honeypot.terminal.nextLine()

        return client.HTTPDownloader.gotHeaders(self, headers)

    def pagePart(self, data):
        if self.status == '200':
            self.currentlength += len(data)

            # if downloading files of unspecified size, this could happen:
            if not self.nomore and self.wget.limit_size > 0 and \
                    self.currentlength > self.wget.limit_size:
                print 'File limit reached, not saving any more data!'
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
            self.wget.write(s.ljust(self.proglen))
            self.proglen = len(s)
            self.lastupdate = time.time()
        return client.HTTPDownloader.pagePart(self, data)

    def pageEnd(self):
        if self.totallength != 0 and self.currentlength != self.totallength:
            return client.HTTPDownloader.pageEnd(self)
        self.wget.write('\r100%%[%s] %s %dK/s' % \
            ('%s>' % (38 * '='),
            splitthousands(str(int(self.totallength))).ljust(12),
            self.speed / 1000))
        self.wget.honeypot.terminal.nextLine()
        self.wget.honeypot.terminal.nextLine()
        self.wget.writeln(
            '%s (%d KB/s) - `%s\' saved [%d/%d]' % \
            (time.strftime('%Y-%m-%d %H:%M:%S'),
            self.speed / 1000,
            self.fakeoutfile, self.currentlength, self.totallength))
        self.wget.fs.mkfile(self.fakeoutfile, 0, 0, self.totallength, 33188)
        self.wget.fs.update_realfile(
            self.wget.fs.getfile(self.fakeoutfile),
            self.wget.safeoutfile)
        return client.HTTPDownloader.pageEnd(self)

# vim: set sw=4 et:
