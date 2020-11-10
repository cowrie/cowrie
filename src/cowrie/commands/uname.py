# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
uname command
"""

from __future__ import absolute_import, division

import getopt

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand


commands = {}

uname_info = {
    "kernel_name": CowrieConfig().get('shell', 'kernel_name', fallback='Linux'),
    "kernel_version": CowrieConfig().get('shell', 'kernel_version', fallback='3.2.0-4-amd64'),
    "kernel_build_string": CowrieConfig().get('shell', 'kernel_build_string', fallback='#1 SMP Debian 3.2.68-1+deb7u1'),
    "hardware_platform": CowrieConfig().get('shell', 'hardware_platform', fallback='x86_64'),
    "operating_system": CowrieConfig().get('shell', 'operating_system', fallback='GNU/Linux')
}


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


def uname_version():
    return """uname (GNU coreutils) 8.25
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie.
"""


class command_uname(HoneyPotCommand):

    def full_uname(self):
        return '{} {} {} {} {} {} {} {}\n'.format(uname_info['kernel_name'],
                                                  self.protocol.hostname,
                                                  uname_info['kernel_version'],
                                                  uname_info['kernel_build_string'],
                                                  uname_info['hardware_platform'],
                                                  uname_info['operating_system'])

    def call(self):
        if not self.args:
            # If no params, output default
            self.write('{}\n'.format(uname_info['kernel_name']))
        else:
            # We have parameters to parse
            try:
                opts, args = getopt.getopt(self.args,
                                           "asnrvmpio",
                                           ["all", "kernel-name", "nodename", "kernel-release", "kernel-version",
                                            "machine", "processor", "hardware-platform", "operating-system", "help",
                                            "version"])
            except getopt.GetoptError:
                uname_help()
                return

            print_help = False
            print_version = False
            print_all = False
            print_kernel_name = False
            print_nodename = False
            print_kernel_release = False
            print_kernel_version = False
            print_machine = False
            print_procesor = False
            print_hardware_platform = False
            print_operating_system = False

            # parse the command line options
            for o, a in opts:
                if o == "--help":
                    print_help = True
                elif o == "--version":
                    print_version = True
                elif o in ("-a", "--all"):
                    print_all = True
                elif o in ("-s", "--kernel-name"):
                    print_kernel_name = True
                elif o in ("-n", "--nodename"):
                    print_nodename = True
                elif o in ("-r", "--kernel-release"):
                    print_kernel_release = True
                elif o in ("-v", "--kernel-version"):
                    print_kernel_version = True
                elif o in ("-m", "--machine"):
                    print_machine = True
                elif o in ("-p", "--procesor"):
                    print_procesor = True
                elif o in ("-i", "--hardware-platform"):
                    print_hardware_platform = True
                elif o in ("-o", "--operating-system"):
                    print_operating_system = True

            # print out information based on command line options
            if print_help:
                self.write(uname_help())
            elif print_version:
                self.write(uname_version())
            elif print_all:
                self.write(self.full_uname())
            else:
                info = []
                if print_kernel_name:
                    info.append(uname_info['kernel_name'])
                if print_nodename:
                    info.append(self.protocol.hostname)
                if print_kernel_release:
                    info.append(uname_info['kernel_version'])
                if print_kernel_version:
                    info.append(uname_info['kernel_build_string'])
                if print_machine:
                    info.append(uname_info['hardware_platform'])
                if print_procesor:
                    info.append(uname_info['hardware_platform'])
                if print_hardware_platform:
                    info.append(uname_info['hardware_platform'])
                if print_operating_system:
                    info.append(uname_info['operating_system'])
                self.write('{}\n'.format(' '.join(info)))


commands['/bin/uname'] = command_uname
commands['uname'] = command_uname
