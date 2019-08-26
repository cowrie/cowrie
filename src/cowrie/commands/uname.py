# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
uname command
"""

from __future__ import absolute_import, division

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}


def hardware_platform():
    return CowrieConfig().get('shell', 'hardware_platform', fallback='x86_64')


def kernel_name():
    return CowrieConfig().get('shell', 'kernel_name', fallback='Linux')


def kernel_version():
    return CowrieConfig().get('shell', 'kernel_version', fallback='3.2.0-4-amd64')


def kernel_build_string():
    return CowrieConfig().get('shell', 'kernel_build_string', fallback='#1 SMP Debian 3.2.68-1+deb7u1')


def operating_system():
    return CowrieConfig().get('shell', 'operating_system', fallback='GNU/Linux')


def uname_help():
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

    def full_uname(self):
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
        opts = {
            'name': False,
            'release': False,
            'version': False,
            'os': False,
            'node': False,
            'machine': False
            }
        if not self.args:
            # IF no params output default
            self.write('{}\n'.format(kernel_name()))
        else:
            # I have parameter to parse
            for a in self.args:
                a = a.strip()
                if a in ('-h', '--help'):
                    self.write(uname_help())
                    return
                elif a in ('-a', '--all'):
                    self.write(self.full_uname())
                    return
                elif a in ('-s', '--kernel-name'):
                    opts['name'] = True
                elif a in ('-r', '--kernel-release'):
                    opts['release'] = True
                elif a in ('-v', '--kernel-version'):
                    opts['version'] = True
                elif a in ('-o', '--operating-system'):
                    opts['os'] = True
                elif a in ('-n', '--nodename'):
                    opts['node'] = True
                elif a in ('-m', '--machine', '-p', '--processor', '-i', '--hardware-platform'):
                    opts['machine'] = True
            '''
            I have all the option set
            '''
            if opts['name']:
                self.write('{} '.format(kernel_name()))
            if opts['node']:
                self.write('{} '.format(self.protocol.hostname))
            if opts['release']:
                self.write('{} '.format(kernel_version()))
            if opts['version']:
                self.write('{} '.format(kernel_build_string()))
            if opts['machine']:
                self.write('{} '.format(hardware_platform()))
            if opts['os']:
                self.write('{} '.format(operating_system()))
            self.write('\n')


commands['/bin/uname'] = command_uname
commands['uname'] = command_uname
