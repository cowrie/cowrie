from core.Kippo import HoneyPotCommand
from core.fstypes import *
import stat, time, urlparse, random

class command_tar(HoneyPotCommand):

    def call(self, args):
        if len(args.split()) < 2:
            self.honeypot.writeln('tar: You must specify one of the `-Acdtrux\' options')
            self.honeypot.wirteln('Try `tar --help\' or `tar --usage\' for more information.')
            return

        filename = args.split()[1]

        path = self.honeypot.fs.resolve_path(filename, self.honeypot.cwd)
        if not path or not self.honeypot.fs.exists(path):
            self.honeypot.writeln('tar: rs: Cannot open: No such file or directory')
            self.honeypot.writeln('tar: Error is not recoverable: exiting now')
            self.honeypot.writeln('tar: Child returned status 2')
            self.honeypot.writeln('tar: Error exit delayed from previous errors')
            return

        cwd = self.honeypot.fs.get_path(self.honeypot.cwd)
        for f in (
                'tiffany1.jpg',
                'tiffany3.jpg',
                'tiffany4.jpg',
                'tiffany5.jpg',
                'tiffany6.jpg',
                'XxX Anal Thunder 5 XxX.AVI',
                ):
            size = 1000000 + int(random.random() * 4000000)
            cwd.append((
                f, T_FILE, 0, 0, size, 33188, time.time(), [], None))
            self.honeypot.writeln('./%s' % f)
