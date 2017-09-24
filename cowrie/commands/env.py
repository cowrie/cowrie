
from __future__ import division, absolute_import

from twisted.internet import reactor

from cowrie.shell.honeypot import HoneyPotCommand

commands = {}

"""
env: invalid option -- 'h'
Try `env --help' for more information.
"""

"""
Usage: env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
Set each NAME to VALUE in the environment and run COMMAND.

  -i, --ignore-environment  start with an empty environment
  -0, --null           end each output line with 0 byte rather than newline
  -u, --unset=NAME     remove variable from the environment
      --help     display this help and exit
      --version  output version information and exit

A mere - implies -i.  If no COMMAND, print the resulting environment.

Report env bugs to bug-coreutils@gnu.org
GNU coreutils home page: <http://www.gnu.org/software/coreutils/>
General help using GNU software: <http://www.gnu.org/gethelp/>
For complete documentation, run: info coreutils 'env invocation'
"""


class command_env(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        for i in list(self.environ.keys()):
            self.write(b"%s=%s\n" % (i,self.environ[i]))


commands['/usr/bin/env'] = command_env
