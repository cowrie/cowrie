from __future__ import annotations
from cowrie.shell.command import HoneyPotCommand
import datetime
import getopt

commands = {}

FINGER_HELP = """Usage:"""


class Command_finger(HoneyPotCommand):
    def call(self):
        time = datetime.datetime.utcnow()
        user_data = []
        # Get all user data and convert to string
        all_users_byte = self.fs.file_contents("/etc/passwd")
        all_users = all_users_byte.decode("utf-8")
        # Convert all new lines to : character
        all_users = all_users.replace("\n", ":")
        # Convert into list by splitting string
        all_users_list = all_users.split(":")
        # Loop over the data in sets of 7
        for i in range(0, len(all_users_list), 7):
            x = i
            # Ensure any added list contains data and is not a blank space by >
            if len(all_users_list[x : x + 7]) != 1:
                # Take the next 7 elements and put them a list, then add to 2d>
                user_data.append(all_users_list[x : x + 7])
        # THIS CODE IS FOR DEBUGGING self.write(str(user_data))

        # If finger called without args
        if len(self.args) == 0:
            self.write("Login\tName\tTty  Idle\tLogin Time  Office  Office Phone\n")
            for i in range(len(user_data)):
                if len(str(user_data[i][0])) > 6:
                    if len(str(user_data[i][4])) > 6:
                        self.write(
                            "{}+ {}+ *:{}\t\t{} (:{})\n".format(
                                str(user_data[i][0])[:6],
                                str(user_data[i][4])[:6],
                                str(user_data[i][2]),
                                str(time.strftime("%b %d %H:%M")),
                                str(user_data[i][3]),
                            )
                        )
                    else:
                        self.write(
                            "{}+ {}\t*:{}\t\t{} (:{})\n".format(
                                str(user_data[i][0])[:6],
                                str(user_data[i][4]),
                                str(user_data[i][2]),
                                str(time.strftime("%b %d %H:%M")),
                                str(user_data[i][3]),
                            )
                        )
                else:
                    if len(str(user_data[i][4])) > 6:
                        self.write(
                            "{}\t{}+ *:{}\t\t{} (:{})\n".format(
                                str(user_data[i][0]),
                                str(user_data[i][4])[:6],
                                str(user_data[i][2]),
                                str(time.strftime("%b %d %H:%M")),
                                str(user_data[i][3]),
                            )
                        )
                    else:
                        self.write(
                            "{}\t{}\t*:{}\t\t{} (:{})\n".format(
                                str(user_data[i][0]),
                                str(user_data[i][4]),
                                str(user_data[i][2]),
                                str(time.strftime("%b %d %H:%M")),
                                str(user_data[i][3]),
                            )
                        )
                # self.write(f"name: %20." + str(user_data[i][0]) + "\n")      >
            # time = datetime.datetime.utcnow()
            # self.write("{}\n".format(time.strftime("%a %b %d %H:%M:%S UTC %Y">
            return

        if len(self.args):
            try:
                opts, args = getopt.gnu_getopt(self.args, "")
            except getopt.GetoptError as err:
                self.errorWrite(
                    f"""finger: invalid option -- '{err.opt}'
usage: finger [-lmps] [login ...]\n"""
                )
                return
        # If args given not any predefined, assume is username
        if len(args) > 0:
            for i in range(len(user_data)):
                # Run if check to check if user is real
                if args[0] == user_data[i][0]:
                    # Display user data
                    self.write(
                        """Login: """
                        + str(user_data[i][0])
                        + """                               Name: """
                        + str(user_data[i][4])
                        + """
Directory: """
                        + str(user_data[i][5])
                        + """             Shell: """
                        + str(user_data[i][6])
                        + """
On since """
                        + str(time.strftime("%a %b %d %H:%M"))
                        + """ (UTC) on :0 from :0 (messages off)
No mail.
No Plan.
"""
                    )
                    return
            # If user is NOT real inform user
            self.write(f"finger: {args[0]}: no such user\n")

            # IF TIME ALLOWS: Seperate into multiple functions
            # IF TIME ALLOWS: Make my comments more concise and remove debuggi>
            return
        # Base.py has some helpful stuff
        return


commands["bin/finger"] = Command_finger
commands["finger"] = Command_finger
