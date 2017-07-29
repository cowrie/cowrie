# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

import random

from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

O_O, O_Q, O_P = 1, 2, 3

class command_adduser(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        self.username = None
        self.item = 0
        for arg in self.args:
            if arg.startswith('-') or arg.isdigit():
                continue
            self.username = arg
            break
        if self.username is None:
            self.write(b'adduser: Only one or two names allowed.\n')
            self.exit()
            return

        self.output = [
            (O_O, b'Adding user `%(username)s\' ...\n'),
            (O_O, b'Adding new group `%(username)s\' (1001) ...\n'),
            (O_O, b'Adding new user `%(username)s\' (1001) with group `%(username)s\' ...\n'),
            (O_O, b'Creating home directory `/home/%(username)s\' ...\n'),
            (O_O, b'Copying files from `/etc/skel\' ...\n'),
            (O_P, b'Password: '),
            (O_P, b'Password again: '),
            (O_O, b'\nChanging the user information for %(username)s\n'),
            (O_O, b'Enter the new value, or press ENTER for the default\n'),
            (O_Q, b'        Username []: '),
            (O_Q, b'        Full Name []: '),
            (O_Q, b'        Room Number []: '),
            (O_Q, b'        Work Phone []: '),
            (O_Q, b'        Home Phone []: '),
            (O_Q, b'        Mobile Phone []: '),
            (O_Q, b'        Country []: '),
            (O_Q, b'        City []: '),
            (O_Q, b'        Language []: '),
            (O_Q, b'        Favorite movie []: '),
            (O_Q, b'        Other []: '),
            (O_Q, b'Is the information correct? [Y/n] '),
            (O_O, b'ERROR: Some of the information you entered is invalid\n'),
            (O_O, b'Deleting user `%(username)s\' ...\n'),
            (O_O, b'Deleting group `%(username)s\' (1001) ...\n'),
            (O_O, b'Deleting home directory `/home/%(username)s\' ...\n'),
            (O_Q, b'Try again? [Y/n] '),
            ]
        self.do_output()


    def do_output(self):
        """
        """
        if self.item == len(self.output):
            self.item = 7
            self.schedule_next()
            return

        l = self.output[self.item]
        self.write(l[1] % {'username': self.username})
        if l[0] == O_P:
            self.protocol.password_input = True
            return
        if l[0] == O_Q:
            return
        else:
            self.item += 1
            self.schedule_next()


    def schedule_next(self):
        """
        """
        self.scheduled = reactor.callLater(
            0.5 + random.random() * 1, self.do_output)


    def lineReceived(self, line):
        """
        """
        if self.item + 1 == len(self.output) and line.strip() in ('n', 'no'):
            self.exit()
            return
        elif self.item == 20 and line.strip() not in ('y', 'yes'):
            self.item = 7
            self.write(b'Ok, starting over\n')
        elif not len(line) and self.output[self.item][0] == O_Q:
            self.write(b'Must enter a value!\n')
        else:
            self.item += 1
        self.schedule_next()
        self.protocol.password_input = False

commands['/usr/sbin/adduser'] = command_adduser
commands['/usr/sbin/useradd'] = command_adduser

# vim: set sw=4 et tw=0:
