from core.honeypot import HoneyPotCommand
import time, random

commands = {}

class command_tar(HoneyPotCommand):

    def call(self, args):
        if len(args.split()) < 2:
            self.writeln('tar: You must specify one of the `-Acdtrux\' options')
            self.writeln('Try `tar --help\' or `tar --usage\' for more information.')
            return

        filename = args.split()[1]

        path = self.fs.resolve_path(filename, self.honeypot.cwd)
        if not path or not self.honeypot.fs.exists(path):
            self.writeln('tar: rs: Cannot open: No such file or directory')
            self.writeln('tar: Error is not recoverable: exiting now')
            self.writeln('tar: Child returned status 2')
            self.writeln('tar: Error exit delayed from previous errors')
            return

        for f in (
                'tiffany1.jpg',
                'tiffany3.jpg',
                'tiffany4.jpg',
                'tiffany5.jpg',
                'tiffany6.jpg',
                'XxX Anal Thunder 5 XxX.AVI',
                ):
            size = 1000000 + int(random.random() * 4000000)
            self.fs.mkfile('%s/%s' % (self.honeypot.cwd, f), 0, 0, size, 33188)
            self.writeln('./%s' % f)
commands['/bin/tar'] = command_tar

# vim: set sw=4 et:
