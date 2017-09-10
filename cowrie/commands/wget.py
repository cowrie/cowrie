# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

import time
import re
import os
import getopt
from OpenSSL import SSL

from twisted.web import client
from twisted.internet import reactor, ssl
from twisted.python import log, compat

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *
from cowrie.core import artifact

"""
"""

commands = {}

def tdiff(seconds):
    """
    """
    t = seconds
    days = int(t / (24 * 60 * 60))
    t -= (days * 24 * 60 * 60)
    hours = int(t / (60 * 60))
    t -= (hours * 60 * 60)
    minutes = int(t / 60)
    t -= (minutes * 60)

    s = '%ds' % (int(t),)
    if minutes >= 1: s = '%dm %s' % (minutes, s)
    if hours >= 1: s = '%dh %s' % (hours, s)
    if days >= 1: s = '%dd %s' % (days, s)
    return s



def sizeof_fmt(num):
    """
    """
    for x in ['bytes','K','M','G','T']:
        if num < 1024.0:
            return "%d%s" % (num, x)
        num /= 1024.0



# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands( s, sep=','):
    """
    """
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]



class command_wget(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        try:
            optlist, args = getopt.getopt(self.args, 'cqO:P:', 'header=')
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

        destination = None
        self.quiet = False
        for opt in optlist:
            if opt[0] == '-O':
                destination = opt[1]
            if opt[0] == '-q':
                self.quiet = True

        if '://' not in url:
            url = 'http://%s' % url

        urldata = compat.urllib_parse.urlparse(url)
        url = bytes(url)

        if destination is None:
            destination = urldata.path.split('/')[-1]
            if not len(destination.strip()) or not urldata.path.count('/'):
                destination = 'index.html'

        destination = self.fs.resolve_path(destination, self.protocol.cwd)
        path = os.path.dirname(destination)
        if not path or \
                not self.fs.exists(path) or \
                not self.fs.isdir(path):
            self.write('wget: %s: Cannot open: No such file or directory\n' % \
                destination)
            self.exit()
            return

        self.url = url

        self.artifactfp = artifact.Artifact(self.protocol.cfg, '%s_%s_%s_%s' % \
                      (time.strftime('%Y%m%d%H%M%S'),
                       self.protocol.getProtoTransport().transportId,
                       self.protocol.terminal.transport.session.id,
                       re.sub('[^A-Za-z0-9]', '_', url)))

        self.deferred = self.download(url, destination, self.artifactfp)
        if self.deferred:
            self.deferred.addCallback(self.success, destination)
            self.deferred.addErrback(self.error, url)


    def download(self, url, outfile, artifactfp, *args, **kwargs):
        """
        """
        try:
            parsed = compat.urllib_parse.urlparse(url)
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == 'https' else 80)
            path = parsed.path or '/'
            if scheme != 'http' and scheme != 'https':
                raise NotImplementedError
            if not host:
                self.exit()
                return None
        except:
            self.write('%s: Unsupported scheme.\n' % (url,))
            self.exit()
            return None

        if self.quiet == False:
            self.write('--%s--  %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), url))
            self.write('Connecting to %s:%d... connected.\n' % (host, port))
            self.write('HTTP request sent, awaiting response... ')

        factory = HTTPProgressDownloader(
            self, outfile, url, artifactfp, *args, **kwargs)

        out_addr = None
        if self.protocol.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.protocol.cfg.get('honeypot', 'out_addr'), 0)

        if scheme == 'https':
            contextFactory = ssl.ClientContextFactory()
            contextFactory.method = SSL.SSLv23_METHOD
            self.connection = reactor.connectSSL(
                host, port, factory, contextFactory, bindAddress=out_addr)
        elif scheme == 'http':
            self.connection = reactor.connectTCP(
                host, port, factory, bindAddress=out_addr)
        else:
            raise NotImplementedError

        return factory.deferred


    def handle_CTRL_C(self):
        self.write('^C\n')
        self.connection.transport.loseConnection()


    def success(self, data, outfile):
        """
        """
        log.msg("WGET SUCCESS!")
        shasum, hash_path, size = self.artifactfp.finish()

        self.protocol.logDispatch(eventid='cowrie.session.file_download',
                                  format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                                  url=self.url,
                                  outfile=hash_path,
                                  shasum=shasum)

        # Update the honeyfs to point to downloaded file
        self.wget.fs.mkfile(self.outfile, 0, 0, size, 33188)
        self.fs.update_realfile(self.fs.getfile(outfile), hash_path)
        self.fs.chown(outfile, self.protocol.user.uid, self.protocol.user.gid)
        self.exit()


    def error(self, error,url):

        if hasattr(error, 'getErrorMessage'): # exceptions
            errorMessage = error.getErrorMessage()
            self.write(errorMessage +'\n')
            # Real wget also adds this:
        if hasattr(error, 'webStatus') and hasattr(error,'webMessage'): # exceptions
            dateWithError = '{} ERROR '.format(time.strftime('%Y-%m-%d %T'))
            self.write(dateWithError + str(error.webStatus) + ': ' + error.webMessage + '\n')
        else:
            self.write('{} ERROR 404: Not Found.\n'.format(time.strftime('%Y-%m-%d %T')))
        self.exit()

commands['/usr/bin/wget'] = command_wget
commands['/usr/bin/dget'] = command_wget

# From http://code.activestate.com/recipes/525493/
class HTTPProgressDownloader(client.HTTPDownloader):
    def __init__(self, wget, outfile, url, artifactfp, headers=None):
        client.HTTPDownloader.__init__(self, url, artifactfp, headers=headers,
            agent=b'Wget/1.11.4')
        self.status = None
        self.wget = wget
        self.outfile = outfile
        self.lastupdate = 0
        self.started = time.time()
        self.proglen = 0
        self.nomore = False
        self.quiet = self.wget.quiet


    def noPage(self, reason): # Called for non-200 responses
        """
        """
        if self.status == '304':
            client.HTTPDownloader.page(self, '')
        else:
            if hasattr(self, 'status'):
                reason.webStatus = self.status
            if hasattr(self, 'message'):
                reason.webMessage = self.message

            client.HTTPDownloader.noPage(self, reason)


    def gotHeaders(self, headers):
        """
        """
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
                    self.wget.write('Length: unspecified [{}]\n'.format(self.contenttype))
            if self.quiet == False:
                self.wget.write('Saving to: `{}\'\n\n'.format(self.outfile))

        return client.HTTPDownloader.gotHeaders(self, headers)


    def pagePart(self, data):
        """
        """
        if self.status == '200':
            self.currentlength += len(data)

            if (time.time() - self.lastupdate) < 0.5:
                return client.HTTPDownloader.pagePart(self, data)
            if self.totallength:
                percent = int(self.currentlength/self.totallength*100)
                spercent = "{}%".format(percent)
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
        """
        """
        if self.totallength != 0 and self.currentlength != self.totallength:
            return client.HTTPDownloader.pageEnd(self)
        if self.quiet == False:
            self.wget.write('\r100%%[%s] %s %dK/s' % \
                ('%s>' % (38 * '='),
                splitthousands(str(int(self.totallength))).ljust(12),
                self.speed / 1000))
            self.wget.write('\n\n')
            self.wget.write(
                '%s (%d KB/s) - `%s\' saved [%d/%d]\n\n' % \
                (time.strftime('%Y-%m-%d %H:%M:%S'),
                self.speed / 1000,
                self.outfile, self.currentlength, self.totallength))

        return client.HTTPDownloader.pageEnd(self)
