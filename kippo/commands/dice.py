# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# Random commands when running new executables

from kippo.core.honeypot import HoneyPotCommand

commands = {}
clist = []

class command_orly(HoneyPotCommand):
    def start(self):
        self.orly()

    def orly(self):
        self.writeln('  ___ ')
        self.writeln(' {o,o}')
        self.writeln(' |)__)')
        self.writeln(' -"-"-')
        self.write('O RLY? ')

    def lineReceived(self, data):
        if data.strip().lower() in ('ya', 'yarly', 'ya rly', 'yes', 'y'):
            self.writeln('  ___')
            self.writeln(' {o,o}')
            self.writeln(' (__(|')
            self.writeln(' -"-"-')
            self.writeln('NO WAI!')
            self.exit()
            return
        self.orly()
clist.append(command_orly)

class command_wargames(HoneyPotCommand):
    def start(self):
        self.write('Shall we play a game? ')

    def lineReceived(self, data):
        self.writeln('A strange game. ' + \
            'The only winning move is not to play.  ' + \
            'How about a nice game of chess?')
        self.exit()
clist.append(command_wargames)

class command_libgnome(HoneyPotCommand):
    def call(self):
        self.writeln('error while loading shared libraries: libgnome.so.32: cannot open shared object file: No such file or directory')
clist.append(command_libgnome)

class command_xconnect(HoneyPotCommand):
    def call(self):
        self.writeln('unable to open display ":0"')
clist.append(command_xconnect)

# vim: set sw=4 et:
