# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks
from kippo.core.honeypot import HoneyPotCommand
import random, re

commands = {}

O_O, O_Q, O_P = 1, 2, 3

class command_adduser(HoneyPotCommand):
    def start(self):
        self.username = None
        self.item = 0
        for arg in self.args:
            if arg.startswith('-') or arg.isdigit():
                continue
            self.username = arg
            break
        if self.username is None:
            self.writeln('adduser: Only one or two names allowed.')
            self.exit()
            return

        self.output = [
            (O_O, 'Adding user `%(username)s\' ...\n'),
            (O_O, 'Adding new group `%(username)s\' (1001) ...\n'),
            (O_O, 'Adding new user `%(username)s\' (1001) with group `%(username)s\' ...\n'),
            (O_O, 'Creating home directory `/home/%(username)s\' ...\n'),
            (O_O, 'Copying files from `/etc/skel\' ...\n'),
            (O_P, 'Password: '),
            (O_P, 'Password again: '),
            (O_O, '\nChanging the user information for %(username)s\n'),
            (O_O, 'Enter the new value, or press ENTER for the default\n'),
            (O_Q, '        Username []: '),
            (O_Q, '        Full Name []: '),
            (O_Q, '        Room Number []: '),
            (O_Q, '        Work Phone []: '),
            (O_Q, '        Home Phone []: '),
            (O_Q, '        Mobile Phone []: '),
            (O_Q, '        Country []: '),
            (O_Q, '        City []: '),
            (O_Q, '        Language []: '),
            (O_Q, '        Favorite movie []: '),
            (O_Q, '        Other []: '),
            (O_Q, 'Is the information correct? [Y/n] '),
            (O_O, 'ERROR: Some of the information you entered is invalid\n'),
            (O_O, 'Deleting user `%(username)s\' ...\n'),
            (O_O, 'Deleting group `%(username)s\' (1001) ...\n'),
            (O_O, 'Deleting home directory `/home/%(username)s\' ...\n'),
            (O_Q, 'Try again? [Y/n] '),
            ]
        self.do_output()

    def do_output(self):
        if self.item == len(self.output):
            self.item = 7
            self.schedule_next()
            return

        l = self.output[self.item]
        self.write(l[1] % {'username': self.username})
        if l[0] == O_P:
            self.honeypot.password_input = True
            return
        if l[0] == O_Q:
            return
        else:
            self.item += 1
            self.schedule_next()

    def schedule_next(self):
        self.scheduled = reactor.callLater(
            0.5 + random.random() * 1, self.do_output)

    def lineReceived(self, line):
        if self.item + 1 == len(self.output) and line.strip() in ('n', 'no'):
            self.exit()
            return
        elif self.item == 20 and line.strip() not in ('y', 'yes'):
            self.item = 7
            self.writeln('Ok, starting over')
        elif not len(line) and self.output[self.item][0] == O_Q:
            self.writeln('Must enter a value!')
        else:
            self.item += 1
        self.schedule_next()
        self.honeypot.password_input = False
commands['/usr/sbin/adduser'] = command_adduser
commands['/usr/sbin/useradd'] = command_adduser

# vim: set sw=4 et tw=0:
