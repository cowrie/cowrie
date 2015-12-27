# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

import optparse

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg

class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status

class ModifiedOptionParser(optparse.OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)


class command_iptables(HoneyPotCommand):
    # Do not resolve args
    resolve_args = False

    # iptables app name
    APP_NAME = "iptables"

    # iptables app version, used in help messages etc.
    APP_VERSION = "v1.4.14"

    # Default iptable table
    DEFAULT_TABLE = "filter"

    def user_is_root(self):
        return self.protocol.user.username == 'root'

    def start(self):
        """
        Emulate iptables commands, including permission checking.

        Verified examples:
        * iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
        * iptables -A INPUT -i eth0 -p tcp -s "127.0.0.1" -j DROP

        Others:
        * iptables
        * iptables [[-t | --table] <name>] [-h | --help]
        * iptables [[-t | --table] <name>] [-v | --version]
        * iptables [[-t | --table] <name>] [-F | --flush] <chain>
        * iptables [[-t | --table] <name>] [-L | --list] <chain>
        * iptables [[-t | --table] <name>] [-S | --list-rules] <chain>
        * iptables --this-is-invalid
        """

        # In case of no arguments
        if len(self.args) == 0:
            self.no_command()
            return

        # Utils
        def optional_arg(arg_default):
            def func(option,opt_str,value,parser):
                if parser.rargs and not parser.rargs[0].startswith('-'):
                    val=parser.rargs[0]
                    parser.rargs.pop(0)
                else:
                    val=arg_default
                setattr(parser.values,option.dest,val)
            return func

        # Initialize options
        parser = ModifiedOptionParser(add_help_option=False)
        parser.add_option("-h", "--help", dest="help", action="store_true")
        parser.add_option("-V", "--version", dest="version", action="store_true")
        parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
        parser.add_option("-x", "--exact", dest="exact", action="store_true")
        parser.add_option("--line-numbers", dest="line_numbers", action="store_true")
        parser.add_option("-n", "--numeric", dest="numeric", action="store_true")
        parser.add_option("--modprobe", dest="modprobe", action="store")

        parser.add_option("-t", "--table", dest="table", action="store", default=command_iptables.DEFAULT_TABLE)
        parser.add_option("-F", "--flush", dest="flush", action="callback", callback=optional_arg(True))
        parser.add_option("-Z", "--zero", dest="zero", action="callback", callback=optional_arg(True))
        parser.add_option("-S", "--list-rules", dest="list_rules", action="callback", callback=optional_arg(True))
        parser.add_option("-L", "--list", dest="list", action="callback", callback=optional_arg(True))
        parser.add_option("-A", "--append", dest="append", action="store")
        parser.add_option("-D", "--delete", dest="delete", action="store")
        parser.add_option("-I", "--insert", dest="insert", action="store")
        parser.add_option("-R", "--replace", dest="replace", action="store")
        parser.add_option("-N", "--new-chain", dest="new_chain", action="store")
        parser.add_option("-X", "--delete-chain", dest="delete_chain", action="store")
        parser.add_option("-P", "--policy", dest="policy", action="store")
        parser.add_option("-E", "--rename-chain", dest="rename_chain", action="store")

        parser.add_option("-p", "--protocol", dest="protocol", action="store")
        parser.add_option("-s", "--source", dest="source", action="store")
        parser.add_option("-d", "--destination", dest="destination", action="store")
        parser.add_option("-j", "--jump", dest="jump", action="store")
        parser.add_option("-g", "--goto", dest="goto", action="store")
        parser.add_option("-i", "--in-interface", dest="in_interface", action="store")
        parser.add_option("-o", "--out-interface", dest="out_interface", action="store")
        parser.add_option("-f", "--fragment", dest="fragment", action="store_true")
        parser.add_option("-c", "--set-counters", dest="set_counters", action="store")
        parser.add_option("-m", "--match", dest="match", action="store")

        parser.add_option("--sport", "--source-ports", dest="source_ports", action="store")
        parser.add_option("--dport", "--destination-ports", dest="dest_ports", action="store")
        parser.add_option("--ports", dest="ports", action="store")
        parser.add_option("--state", dest="state", action="store")


        # Parse options or display no files
        try:
            (opts, args) = parser.parse_args(list(self.args))
        except OptionParsingError as e:
            self.bad_argument(self.args[0])
            return
        except OptionParsingExit as e:
            self.unknown_option(e)
            return

        # Initialize table
        if not self.setup_table(opts.table):
            return

        # Parse options
        if opts.help:
            self.show_help()
            return
        elif opts.version:
            self.show_version()
            return
        elif opts.flush:
            self.flush("" if opts.flush == True else opts.flush)
            return
        elif opts.list:
            self.list("" if opts.list == True else opts.list)
            return
        elif opts.list_rules:
            self.list_rules("" if opts.list_rules == True else opts.list_rules)
            return

        # Done
        self.exit()

    def setup_table(self, table):
        """
        Called during startup to make sure the current environment has some
        fake rules in memory.
        """

        # Create fresh tables on start
        if not hasattr(self.protocol.user.server, 'iptables'):
            setattr(self.protocol.user.server, 'iptables', {
                "raw": {
                    "PREROUTING": [],
                    "OUTPUT": []
                },
                "filter": {
                    "INPUT": [
                        ('ACCEPT', 'tcp', '--', 'anywhere', 'anywhere', 'tcp', 'dpt:ssh'),
                        ('DROP', 'all', '--', 'anywhere', 'anywhere', '', '')
                    ],
                    "FORWARD": [],
                    "OUTPUT": []
                },
                "mangle": {
                    "PREROUTING": [],
                    "INPUT": [],
                    "FORWARD": [],
                    "OUTPUT": [],
                    "POSTROUTING": []
                },
                "nat": {
                    "PREROUTING": [],
                    "OUTPUT": []
                }
            })

        # Get the tables
        self.tables = getattr(self.protocol.user.server, 'iptables')

        # Verify selected table
        if not self.is_valid_table(table):
            return False

        # Set table
        self.current_table = self.tables[table]

        # Done
        return True

    def is_valid_table(self, table):
        if self.user_is_root():
            # Verify table existence
            if not table in self.tables.iterkeys():
                self.write( """%s: can\'t initialize iptables table \'%s\': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.\n""" % (command_iptables.APP_NAME, table) )
                self.exit()
            else:
                # Exists
                return True
        else:
            self.no_permission()

        # Failed
        return False

    def is_valid_chain(self, chain):
        # Verify chain existence. Requires valid table first
        if not chain in self.current_table.iterkeys():
            self.write("%s: No chain/target/match by that name.\n" % command_iptables.APP_NAME)
            self.exit()
            return False

        # Exists
        return True

    def show_version(self):
        """ Show version and exit """
        self.write('%s %s\n' % (command_iptables.APP_NAME, command_iptables.APP_VERSION))
        self.exit()

    def show_help(self):
        """ Show help and exit """

        self.write( """%s %s'

Usage: iptables -[AD] chain rule-specification [options]
       iptables -I chain [rulenum] rule-specification [options]
       iptables -R chain rulenum rule-specification [options]
       iptables -D chain rulenum [options]
       iptables -[LS] [chain [rulenum]] [options]
       iptables -[FZ] [chain] [options]
       iptables -[NX] chain
       iptables -E old-chain-name new-chain-name
       iptables -P chain target [options]
       iptables -h (print this help information)

Commands:
Either long or short options are allowed.
  --append  -A chain       Append to chain
  --delete  -D chain       Delete matching rule from chain
  --delete  -D chain rulenum
               Delete rule rulenum (1 = first) from chain
  --insert  -I chain [rulenum]
               Insert in chain as rulenum (default 1=first)
  --replace -R chain rulenum
               Replace rule rulenum (1 = first) in chain
  --list    -L [chain [rulenum]]
               List the rules in a chain or all chains
  --list-rules -S [chain [rulenum]]
               Print the rules in a chain or all chains
  --flush   -F [chain]     Delete all rules in  chain or all chains
  --zero    -Z [chain [rulenum]]
               Zero counters in chain or all chains
  --new     -N chain       Create a new user-defined chain
  --delete-chain
            -X [chain]     Delete a user-defined chain
  --policy  -P chain target
               Change policy on chain to target
  --rename-chain
            -E old-chain new-chain
               Change chain name, (moving any references)
Options:
[!] --proto    -p proto    protocol: by number or name, eg. \'tcp\'
[!] --source   -s address[/mask][...]
               source specification
[!] --destination -d address[/mask][...]
               destination specification
[!] --in-interface -i input name[+]
               network interface name ([+] for wildcard)
  --jump    -j target
               target for rule (may load target extension)
  --goto      -g chain
                              jump to chain with no return
  --match  -m match
               extended match (may load extension)
  --numeric    -n      numeric output of addresses and ports
[!] --out-interface -o output name[+]
               network interface name ([+] for wildcard)
  --table  -t table    table to manipulate (default: \'filter\')
  --verbose    -v      verbose mode
  --line-numbers       print line numbers when listing
  --exact  -x      expand numbers (display exact values)
[!] --fragment -f      match second or further fragments only
  --modprobe=<command>     try to insert modules using this command
  --set-counters PKTS BYTES    set the counter during insert/append
[!] --version  -V      print package version.\n""" % (command_iptables.APP_NAME, command_iptables.APP_VERSION))
        self.exit()

    def list_rules(self, chain):
        """ List current rules as commands"""

        if self.user_is_root():
            if len(chain) > 0:
                print chain
                # Check chain
                if not self.is_valid_chain(chain):
                    return

                chains = [chain]
            else:
                chains = self.current_table.iterkeys()

            # Output buffer
            output = []

            for chain in chains:
                output.append("-P %s ACCEPT" % chain)

            # Done
            self.write(output+'\n')
            self.exit()
        else:
            self.no_permission()

    def list(self, chain):
        """ List current rules """

        if self.user_is_root():
            if len(chain) > 0:
                print chain
                # Check chain
                if not self.is_valid_chain(chain):
                    return

                chains = [chain]
            else:
                chains = self.current_table.iterkeys()

            # Output buffer
            output = []

            for chain in chains:
                # Chain table header
                chain_output = [
                    "Chain %s (policy ACCEPT)" % chain,
                    "target     prot opt source               destination",
                ]

                # Format the rules
                for rule in self.current_table[chain]:
                    chain_output.append(
                        "%-10s %-4s %-3s %-20s %-20s %s %s" % rule,
                    )

                # Create one string
                output.append("\n".join(chain_output))

            # Done
            self.write("\n\n".join(output)+'\n')
            self.exit()
        else:
            self.no_permission()

    def flush(self, chain):
        """ Mark rules as flushed """

        if self.user_is_root():
            if len(chain) > 0:
                # Check chain
                if not self.is_valid_chain(chain):
                    return

                chains = [chain]
            else:
                chains = self.current_table.iterkeys()

            # Flush
            for chain in chains:
                self.current_table[chain] = []

            self.exit()
        else:
            self.no_permission()

    def no_permission(self):
        self.write( """%s %s: can\'t initialize iptables table \'filter\': Permission denied (you must be root)
Perhaps iptables or your kernel needs to be upgraded.\n"""
            % (command_iptables.APP_NAME, command_iptables.APP_VERSION) )
        self.exit()

    def no_command(self):
        """ Print no command message and exit """

        self.write( """%s %s: no command specified'
Try `iptables -h\' or \'iptables --help\' for more information.\n"""
            % (command_iptables.APP_NAME, command_iptables.APP_VERSION) )
        self.exit()

    def unknown_option(self, option):
        """ Print unknown option message and exit """

        self.write( """%s %s: unknown option \'%s\''
Try `iptables -h\' or \'iptables --help\' for more information.\n"""
            % (command_iptables.APP_NAME, command_iptables.APP_VERSION, option) )
        self.exit()

    def bad_argument(self, argument):
        """ Print bad argument and exit """

        self.write( """Bad argument \'%s\'
Try `iptables -h\' or \'iptables --help\' for more information.\n"""
            % argument )
        self.exit()

# Definition
commands['/sbin/iptables'] = command_iptables
