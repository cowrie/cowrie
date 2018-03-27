from __future__ import division, absolute_import

import getopt

from twisted.python import log

from cowrie.shell.honeypot import HoneyPotCommand

commands = {}


class command_base64(HoneyPotCommand):
    """
    author: Ivan Korolev (@fe7ch)
    """

    def start(self):
        """
        """

        self.mode = 'e'
        self.ignore = False

        try:
            optlist, args = getopt.getopt(self.args, 'diw:', ['version', 'help', 'decode', 'ignore-garbage', 'wrap='])
        except getopt.GetoptError as err:
            self.errorWrite('Unrecognized option\n')
            self.exit()
            return

        for opt in optlist:
            if opt[0] == '--help':
                self.write("""Usage: base64 [OPTION]... [FILE]
Base64 encode or decode FILE, or standard input, to standard output.

Mandatory arguments to long options are mandatory for short options too.
  -d, --decode          decode data
  -i, --ignore-garbage  when decoding, ignore non-alphabet characters
  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76).
                        Use 0 to disable line wrapping

      --help     display this help and exit
      --version  output version information and exit

With no FILE, or when FILE is -, read standard input.

The data are encoded as described for the base64 alphabet in RFC 3548.
When decoding, the input may contain newlines in addition to the bytes of
the formal base64 alphabet.  Use --ignore-garbage to attempt to recover
from any other non-alphabet bytes in the encoded stream.

Report base64 bugs to bug-coreutils@gnu.org
GNU coreutils home page: <http://www.gnu.org/software/coreutils/>
General help using GNU software: <http://www.gnu.org/gethelp/>
For complete documentation, run: info coreutils 'base64 invocation'
""")
                self.exit()
                return
            elif opt[0] == '--version':
                self.write("""base64 (GNU coreutils) 8.21
Copyright (C) 2013 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Simon Josefsson.
""")
                self.exit()
                return
            elif opt[0] == '-d' or opt[0] == '--decode':
                self.mode = 'd'

            elif opt[0] == '-i' or opt[0] == '--ignore-garbage':
                self.ignore = True

            elif opt[0] == '-w' or opt[0] == 'wrap':
                pass

        if self.input_data:
            self.dojob(self.input_data)
        else:
            if len(args) > 1:
                self.errorWrite(
                    """base64: extra operand '%s'
Try 'base64 --help' for more information.
""" % args[0])
                self.exit()
                return

            pname = self.fs.resolve_path(args[0], self.protocol.cwd)
            if not self.fs.isdir(pname):
                try:
                    self.dojob(self.fs.file_contents(pname))
                except Exception as e:
                    print(str(e))
                    self.errorWrite('base64: {}: No such file or directory\n'.format(args[0]))
            else:
                self.errorWrite('base64: read error: Is a directory\n')

        self.exit()

    def dojob(self, s):
        if self.ignore:
            s = ''.join([i for i in s if i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='])

        if self.mode == 'e':
            self.write(s.encode('base64'))
        else:
            try:
                self.write(s.decode('base64'))
            except:
                self.errorWrite("base64: invalid input\n")

    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.input',
                realm='base64',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

        self.dojob(line)

    def handle_CTRL_D(self):
        self.exit()


commands['/usr/bin/base64'] = command_base64
