#

from __future__ import division, absolute_import

from cowrie.core.config import CONFIG
from configparser import NoOptionError

from cowrie.shell.honeypot import HoneyPotCommand

commands = {}

class command_uname(HoneyPotCommand):

    def help(self):
        return '''Usage: uname [OPTION]...
Print certain system information.  With no OPTION, same as -s.

  -a, --all                print all information, in the following order,
                             except omit -p and -i if unknown:
  -s, --kernel-name        print the kernel name
  -n, --nodename           print the network node hostname
  -r, --kernel-release     print the kernel release
  -v, --kernel-version     print the kernel version
  -m, --machine            print the machine hardware name
  -p, --processor          print the processor type (non-portable)
  -i, --hardware-platform  print the hardware platform (non-portable)
  -o, --operating-system   print the operating system
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/uname>
or available locally via: info '(coreutils) uname invocation'\n
'''

    def hardware_platform(self):
        try:
            return CONFIG.get("honeypot", "hardware_platform")
        except NoOptionError:
            return 'x86_64'

    def kernel_version(self):
        try:
            return CONFIG.get("honeypot", "kernel_version")
        except NoOptionError:
            return '3.2.0-4-amd64'

    def kernel_build_string(self):
        try:
           return CONFIG.get("honeypot", "kernel_build_string")
        except NoOptionError:
           return '#1 SMP Debian 3.2.68-1+deb7u1'

    def operating_system(self):
        return 'GNU/Linux'

    def full_uname(self):
        return 'Linux %s %s %s %s %s\n' % ( self.protocol.hostname,
                                            self.kernel_version(),
                                            self.kernel_build_string(),
                                            self.hardware_platform(),
                                            self.operating_system() )


    def call(self):
        if len(self.args) and self.args[0].strip() in ('-a', '--all'):
            self.write(self.full_uname())
        elif len(self.args) and self.args[0].strip() in ('-r', '--kernel-release'):
            self.write( '%s\n' % self.kernel_version() )
        elif len(self.args) and self.args[0].strip() in ('-o', '--operating-system'):
            self.write( '%s\n' % self.operating_system() )
        elif len(self.args) and self.args[0].strip() in ('-n', '--nodename'):
            self.write( '%s\n' % self.protocol.hostname )
        elif len(self.args) and self.args[0].strip() in ('-m', '--machine', '-p', '--processor', '-i', '--hardware-platform'):
            self.write( '%s\n' % self.hardware_platform() )
        elif len(self.args) and self.args[0].strip() in ('-h', '--help'):
            self.write( self.help() )
        else:
            self.write('Linux\n')

commands['/bin/uname'] = command_uname

