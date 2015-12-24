
from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

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

    def done(self):
        """
        """
        self.exit()


    def start(self):
        """
        """
        for i in list(self.environ.keys()):
            self.write("%s=%s\n" % (i,self.environ[i]))
        self.exit()


commands['/usr/bin/env'] = command_env

# vim: set sw=4 et tw=0:
