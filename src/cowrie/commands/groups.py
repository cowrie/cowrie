from __future__ import annotations
import getopt
from cowrie.shell.command import HoneyPotCommand

commands = {}

GROUPS_HELP = """Usage: groups [OPTION]... [USERNAME]...
Print group memberships for each USERNAME or, if no USERNAME is specified, for
the current process (which may differ if the groups database has changed).
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation at: <https://www.gnu.org/software/coreutils/groups>
or available locally via: info '(coreutils) groups invocation'\n"""

GROUPS_VERSION = """groups (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie and James Youngman.\n"""


class Command_groups(HoneyPotCommand):
    def call(self):
        if len(self.args):
            try:
                opts, args = getopt.gnu_getopt(
                    self.args, "hvr:", ["help", "version", "regexp="]
                )
            except getopt.GetoptError as err:
                self.errorWrite(
                    f"groups: invalid option -- '{err.opt}'\nTry 'groups --help' for more information.\n"
                )
                return

            for vars in opts:
                if vars[0] == "-h" or vars[0] == "--help":
                    self.write(GROUPS_HELP)
                    return
                elif vars[0] == "-v" or vars[0] == "--version":
                    self.write(GROUPS_VERSION)
                    return

            if len(args) > 0:
                file_content = self.fs.file_contents("/etc/group")
                self.output(file_content, args[0])

        else:
            content = self.fs.file_contents("/etc/group")
            self.output(content, "")

    def output(self, file_content, username):
        groups_string = bytes("", encoding="utf-8")
        if not username:
            username = self.protocol.user.username
        else:
            if not self.check_valid_user(username):
                self.write(f"groups: '{username}': no such user\n")
                return
            else:
                ss = username + " : "
                groups_string = bytes(ss, encoding="utf-8")

        groups_list = []
        lines = file_content.split(b"\n")
        usr_string = bytes(username, encoding="utf-8")
        for line in lines:
            if usr_string in line:
                members = line.split(b":")
                groups_list.append(members[0])

        for g in groups_list:
            groups_string += g + b" "

        self.writeBytes(groups_string + b"\n")

    def check_valid_user(self, username):
        usr_byte = bytes(username, encoding="utf-8")
        users = self.fs.file_contents("/etc/shadow")
        lines = users.split(b"\n")
        for line in lines:
            usr_arr = line.split(b":")
            if usr_arr[0] == usr_byte:
                return True
        return False


commands["groups"] = Command_groups
commands["/bin/groups"] = Command_groups
