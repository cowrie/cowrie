# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_which(HoneyPotCommand):
    # Do not resolve args
    resolve_args = False

    def call(self):
        """ Look up all the arguments on PATH and print each (first) result """

        # No arguments, just exit
        if not len(self.args) or not 'PATH' in self.environ:
            return

        # Look up each file
        for f in self.args:
            for path in self.environ['PATH'].split(':'):
                resolved = self.fs.resolve_path(f, path)

                if self.fs.exists(resolved):
                    self.write("%s/%s\n" % (path, f))
                    continue

# Definition
commands['which'] = command_which
