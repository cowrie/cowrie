from core.Kippo import HoneyPotCommand
from core.fstypes import *
import stat, time, urlparse, random

class command_wget(HoneyPotCommand):

    def call(self, args):
        if not len(args):
            self.honeypot.writeln('wget: missing URL')
            self.honeypot.writeln('Usage: wget [OPTION]... [URL]...')
            self.honeypot.terminal.nextLine()
            self.honeypot.writeln('Try `wget --help\' for more options.')
            return

        # ('http', 'www.google.fi', '/test.txt', '', '', '')
        url = urlparse.urlparse(args)
        size = 10000 + int(random.random() * 40000)
        speed = 50 + int(random.random() * 300)

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
            'url':      args,
            'file':     url[2].split('/')[-1],
            'host':     url[1],
            'size':     size,
            'speed':    speed,
            }
        self.honeypot.writeln(output)
        cwd = self.honeypot.fs.get_path(self.honeypot.cwd)
        cwd.append((
            url[2].split('/')[-1],
            T_FILE, 0, 0, size, 33188, time.time(), [], None))
