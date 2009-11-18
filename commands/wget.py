from core.honeypot import HoneyPotCommand
from core.fstypes import *
from twisted.web import client
import stat, time, urlparse, random, re
import config

class command_wget(HoneyPotCommand):

    def call(self, args):
        url = None
        for arg in args.split():
            if arg.startswith('-'):
                continue
            url = arg.strip()

        if not url:
            self.writeln('wget: missing URL')
            self.writeln('Usage: wget [OPTION]... [URL]...')
            self.nextLine()
            self.writeln('Try `wget --help\' for more options.')
            return

        urldata = urlparse.urlparse(url)
        size = 10000 + int(random.random() * 40000)
        speed = 50 + int(random.random() * 300)

        outfile = urldata.path.split('/')[-1]
        if not len(outfile.strip()) or not urldata.path.count('/'):
            outfile = 'index.html'

        output = """
--%(stamp)s--  %(url)s
Connecting to %(host)s:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: `%(file)s'

    [ <=>                                   ] 6,214       --.-K/s   in 0.04s

%(stamp)s (%(speed)s KB/s) - `%(file)s' saved [%(size)s]

""" % {
            'stamp':    time.strftime('%Y-%m-%d %T'),
            'url':      url,
            'file':     outfile,
            'host':     urldata.path.split('/')[0],
            'size':     size,
            'speed':    speed,
            }
        self.writeln(output)
        self.fs.mkfile(
            '%s/%s' % (self.honeypot.cwd, outfile), 0, 0, size, 33188)

        # now just dl the file in background...
        protocol = 'http'
        if len(urldata[0]):
            protocol = urldata.scheme
        url = '%s://%s%s' % (protocol, urldata.netloc, urldata.path)
        fn = '%s_%s' % \
            (time.strftime('%Y%m%d%H%M%S'),
            re.sub('[^A-Za-z0-9]', '_', url))
        d = client.downloadPage(url, file('%s/%s' % \
            (config.download_path, fn), 'w'))
        d.addCallback(self.saveurl, fn)
        d.addErrback(self.error, url)

    def saveurl(self, data, fn):
        print 'File download finished (%s)' % fn

    def error(self, error, url):
        if hasattr(error, 'getErrorMessage'): # exceptions
            error = error.getErrorMessage()
        print 'Error downloading %s: %s' % (url, repr(error))

# vim: set sw=4 et:
