#

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.customparser import CustomParser
from cowrie.core.customparser import OptionNotFound
from cowrie.core.customparser import ExitException

commands = {}

class command_uname(HoneyPotCommand):
    def argparse_error(self, message):
        self.write("uname: %s\nTry 'uname --help' for more information.\n" % message.replace('arguments', 'option'))
        raise OptionNotFound(message)

    def __init__(self, protocol, *args):
        super(command_uname, self).__init__(protocol, *args)

        self.version = self.protocol.cfg.get('uname', 'uname_version', fallback='%(prog)s 8.5').rstrip('\n')
        self.help = self.protocol.cfg.get('uname', 'uname_help', fallback=None)
        self.kernel_name = self.protocol.cfg.get('uname', 'kernel_name', fallback='Linux')
        self.nodename = self.protocol.hostname
        self.kernel_release = self.protocol.cfg.get('uname', 'kernel_release', fallback='3.2.0-4-amd64')
        self.kernel_version = self.protocol.cfg.get('uname', 'kernel_version', fallback='#1 SMP Debian 3.2.68-1+deb7u1')
        self.machine = self.protocol.cfg.get('uname', 'machine', fallback='x86_64')
        self.processor = self.protocol.cfg.get('uname', 'processor', fallback='unknown')
        self.hardware_platform = self.protocol.cfg.get('uname', 'hardware_platform', fallback='unknown')
        self.operating_system = self.protocol.cfg.get('uname', 'operating_system', fallback='GNU/Linux')

    def format_help(self):
        return self.help

    def call(self):
        parser = CustomParser(self, add_help=False)
        parser.prog = 'uname'
        parser.usage = '%(prog)s [OPTIONS]...'
        if self.help:
            parser.format_help = self.format_help
        parser.error = self.argparse_error
        parser.add_argument('-a', '--all', action='store_true', help='print all information, in the following order,\nexcept omit -p and -i if unknown:')
        parser.add_argument('-s', '--kernel-name', action='store_true', help='print the kernel name')
        parser.add_argument('-n', '--nodename', action='store_true', help='print the network node hostname')
        parser.add_argument('-r', '--kernel-release', action='store_true', help='print the kernel release')
        parser.add_argument('-v', '--kernel-version', action='store_true', help='print the kernel version')
        parser.add_argument('-m', '--machine', action='store_true', help='print the machine hardware name')
        parser.add_argument('-p', '--processor', action='store_true', help='print the processor type (non-portable)')
        parser.add_argument('-i', '--hardware-platform', action='store_true', help='print the hardware platform (non-portable)')
        parser.add_argument('-o', '--operating-system', action='store_true', help='print the operating system')
        parser.add_argument('--help', action='help', help='display this help and exit')
        parser.add_argument('--version', help='output version information and exit', action='store_true')

        try:
            args = parser.parse_args(self.args)
            if args.version:
                self.write(self.version + '\n')
                return
            uname_list = []
            if args.all:
                uname_list = [self.kernel_name, self.nodename, self.kernel_release, self.kernel_version, self.machine]
                if self.processor != 'unknown':
                    uname_list.append(self.processor)
                if self.hardware_platform != 'unknown':
                    uname_list.append(self.hardware_platform)
                if self.operating_system != 'unknown':
                    uname_list.append(self.operating_system)
            else:
                if args.kernel_name:
                    uname_list.append(self.kernel_name)
                if args.nodename:
                    uname_list.append(self.nodename)
                if args.kernel_release:
                    uname_list.append(self.kernel_release)
                if args.kernel_version:
                    uname_list.append(self.kernel_version)
                if args.machine:
                    uname_list.append(self.machine)
                if args.processor:
                    uname_list.append(self.processor)
                if args.hardware_platform:
                    uname_list.append(self.hardware_platform)
                if args.operating_system:
                    uname_list.append(self.operating_system)
                if not uname_list:
                    uname_list = [self.kernel_name]

            self.write(' '.join(uname_list) + '\n')

        except OptionNotFound:
            return
        except ExitException:
            return
        except Exception:
            return


commands['/bin/uname'] = command_uname

