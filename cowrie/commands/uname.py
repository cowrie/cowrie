# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
uname command
"""

from __future__ import division, absolute_import
from configparser import NoOptionError

from cowrie.core.config import CONFIG
from cowrie.shell.honeypot import HoneyPotCommand

commands = {}

def hardware_platform():
    """
    """
    try:
        return CONFIG.get('shell', 'hardware_platform')
    except NoOptionError:
        return 'x86_64'



def kernel_name():
    """
    """
    try:
        return CONFIG.get('shell', 'kernel_name')
    except NoOptionError:
        return 'Linux'



def kernel_version():
    """
    """
    try:
        return CONFIG.get('shell', 'kernel_version')
    except NoOptionError:
        return '3.2.0-4-amd64'



def kernel_build_string():
    """
    """
    try:
        return CONFIG.get('shell', 'kernel_build_string')
    except NoOptionError:
        return '#1 SMP Debian 3.2.68-1+deb7u1'



def operating_system():
    """
    """
    try:
        return CONFIG.get('shell', 'operating_system')
    except NoOptionError:
        return 'GNU/Linux'



def uname_help():
    """
    """
    return """Usage: uname [OPTION]...
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
"""



class command_uname(HoneyPotCommand):
    """
    """
    def full_uname(self):
        """
        """
        return '{} {} {} {} {} {}\n'.format(kernel_name(),
                                            self.protocol.hostname,
                                            kernel_version(),
                                            kernel_build_string(),
                                            hardware_platform(),
                                            operating_system())


    def call(self):
        """
        TODO: getopt style parsing
        """
        if not self.args:
            self.write('{}\n'.format(kernel_name()))
        elif self.args[0].strip() in ('-a', '--all'):
            self.write(self.full_uname())
        elif self.args[0].strip() in ('-s', '--kernel-name'):
            self.write('{}\n'.format(kernel_name()))
        elif self.args[0].strip() in ('-r', '--kernel-release'):
            self.write('{}\n'.format(kernel_version()))
        elif self.args[0].strip() in ('-o', '--operating-system'):
            self.write('{}\n'.format(operating_system()))
        elif self.args[0].strip() in ('-n', '--nodename'):
            self.write('{}\n'.format(self.protocol.hostname))
        elif self.args[0].strip() in ('-m', '--machine', '-p', '--processor', '-i', '--hardware-platform'):
            self.write('{}\n'.format(hardware_platform()))
        elif self.args[0].strip() in ('-h', '--help'):
            self.write(uname_help())

commands['/bin/uname'] = command_uname
