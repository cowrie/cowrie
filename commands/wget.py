from core.Kippo import HoneyPotCommand
from core.fstypes import *
from twisted.web import client
import stat, time, urlparse, random, re

class command_wget(HoneyPotCommand):

    def call(self, args):
        url = None
        for arg in args.split():
            if arg.startswith('-'):
                continue
            url = arg.strip()

        if not url:
            self.honeypot.writeln('wget: missing URL')
            self.honeypot.writeln('Usage: wget [OPTION]... [URL]...')
            self.honeypot.terminal.nextLine()
            self.honeypot.writeln('Try `wget --help\' for more options.')
            return

        # ('http', 'www.google.fi', '/test.txt', '', '', '')
        urldata = urlparse.urlparse(url)
        size = 10000 + int(random.random() * 40000)
        speed = 50 + int(random.random() * 300)

        outfile = urldata[2].split('/')[-1]
        if not len(outfile.strip()):
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
            'host':     urldata[1],
            'size':     size,
            'speed':    speed,
            }
        self.honeypot.writeln(output)
        cwd = self.honeypot.fs.get_path(self.honeypot.cwd)
        cwd.append((outfile, T_FILE, 0, 0, size, 33188, time.time(), [], None))

        # now just dl the file in background...
        d = client.getPage(url)
        d.addCallback(self.saveurl, url)
        d.addErrback(self.error, url)

    def saveurl(self, data, url):
        print 'Saving URL %s' % url
        fn = '%s_%s' % \
            (time.strftime('%Y%m%d%H%M%S'),
            re.sub('[^A-Za-z0-9]', '_', url))
        f = file('./dl/%s' % fn, 'w')
        f.write(data)
        f.close()

    def error(self, error, url):
        if hasattr(error, 'getErrorMessage'): # exceptions
            error = error.getErrorMessage()
        print 'Error downloading %s: %s' % (url, repr(error))
