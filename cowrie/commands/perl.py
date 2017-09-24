# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module contains the perl command
"""

from __future__ import division, absolute_import

import getopt

from twisted.python import log

from cowrie.shell.honeypot import HoneyPotCommand

commands = {}


class command_perl(HoneyPotCommand):
    """
    """
    def version(self):
        output = (
            '',
            'This is perl 5, version 14, subversion 2 (v5.14.2) built for x86_64-linux-thread-multi',
            '',
            'Copyright 1987-2014, Larry Wall',
            '',
            'Perl may be copied only under the terms of either the Artistic License or the',
            'GNU General Public License, which may be found in the Perl 5 source kit.',
            '',
            'Complete documentation for Perl, including FAQ lists, should be found on',
            'this system using "man perl" or "perldoc perl".  If you have access to the',
            'Internet, point your browser at http://www.perl.org/, the Perl Home Page.',
            ''
        )
        for l in output:
            self.write(l + '\n')


    def help(self):
        output = (
            '',
            'Usage: perl [switches] [--] [programfile] [arguments]',
            '  -0[octal]         specify record separator (\\0, if no argument)',
            '  -a                autosplit mode with -n or -p (splits $_ into @F)',
            '  -C[number/list]   enables the listed Unicode features',
            '  -c                check syntax only (runs BEGIN and CHECK blocks)',
            '  -d[:debugger]     run program under debugger',
            '  -D[number/list]   set debugging flags (argument is a bit mask or alphabets)',
            "  -e program        one line of program (several -e's allowed, omit programfile)",
            '  -E program        like -e, but enables all optional features',
            "  -f                don't do $sitelib/sitecustomize.pl at startup",
            "  -F/pattern/       split() pattern for -a switch (//'s are optional)",
            '  -i[extension]     edit <> files in place (makes backup if extension supplied)',
            "  -Idirectory       specify @INC/#include directory (several -I's allowed)",
            '  -l[octal]         enable line ending processing, specifies line terminator',
            '  -[mM][-]module    execute "use/no module..." before executing program',
            '  -n                assume "while (<>) { ... }" loop around program',
            '  -p                assume loop like -n but print line also, like sed',
            '  -s                enable rudimentary parsing for switches after programfile',
            '  -S                look for programfile using PATH environment variable',
            '  -t                enable tainting warnings',
            '  -T                enable tainting checks',
            '  -u                dump core after parsing program',
            '  -U                allow unsafe operations',
            '  -v                print version, subversion (includes VERY IMPORTANT perl info)',
            '  -V[:variable]     print configuration summary (or a single Config.pm variable)',
            '  -w                enable many useful warnings (RECOMMENDED)',
            '  -W                enable all warnings',
            '  -x[directory]     strip off text before #!perl line and perhaps cd to directory',
            '  -X                disable all warnings',
            ''
        )
        for l in output:
            self.write(l + '\n')


    def start(self):
        """
        """
        try:
            opts, args = getopt.gnu_getopt(self.args, 'acfhnpsStTuUvwWXC:D:e:E:F:i:I:l:m:M:V:X:')
        except getopt.GetoptError as err:
            self.write("Unrecognized switch: -" + err.opt + " (-h will show valid options).\n")
            self.exit()

        # Parse options
        for o, a in opts:
            if o in ("-v"):
                self.version()
                self.exit()
                return
            elif o in ("-h"):
                self.help()
                self.exit()
                return

        for value in args:
            sourcefile = self.fs.resolve_path(value, self.protocol.cwd)

            if self.fs.exists(sourcefile):
                self.exit()
            else:
                self.write("Can't open perl script \"%s\": No such file or directory\n" % (value))
                self.exit()

        if not len(self.args):
            pass


    def lineReceived(self, line):
        """
        """
        log.msg(eventid='cowrie.command.input',
                realm='perl',
                input=line,
                format='INPUT (%(realm)s): %(input)s')


    def handle_CTRL_D(self):
        """
        """
        self.exit()


commands['/usr/bin/perl'] = command_perl
