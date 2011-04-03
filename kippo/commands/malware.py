# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# Commands mapped to common malware

from kippo.core.honeypot import HoneyPotCommand

commands = {}
clist = {} # names
slist = {} # sizes

# 9729c037cb0a32811ba3eb15e3c8a789
class command_nop(HoneyPotCommand):
    def call(self):
        pass
slist[317] = command_nop
clist['autorun'] = command_nop

# 158c35ecfd4a4a490b613d87a22088fa
class command_start1(HoneyPotCommand):
    def call(self):
        self.writeln('=====>Created by PuFoS<=====')
        self.writeln('++++++ *Asta e o arhiva privata*  ++++++++')
        self.writeln('Exemplu : ./start canal ')
        self.writeln('P.S : FARA DIEZ!')
slist[750] = command_start1
clist['start'] = command_start1

# d4655a3bdcb9e18c6718c29eda91725b
class command_start2(HoneyPotCommand):
    def call(self):
        self.writeln('Exemplu: ./start canal (fara diez)')
slist[608] = command_start2

# 9428fcc48cf2c01668678e9ea4874de4
class command_start3(HoneyPotCommand):
    def call(self):
        self.writeln('####################################################################')
        self.writeln('#                               ______')
        self.writeln('#                            .-.      .-.')
        self.writeln('#                           /            \\')
        self.writeln('#                          |     zRR      |')
        self.writeln('#                          |,  .-.  .-.  ,|')
        self.writeln('#                          | )(z_/  \z_)( |')
        self.writeln('#                          |/     /\     \|')
        self.writeln('#                  _       (_     ^^     _)')
        self.writeln('#          _\ ____) \_______\__|IIIIII|__/_________________________')
        self.writeln('#         (_)[___]{}<________|-\IIIIII/-|__zRR__zRR__zRR___________\\')
        self.writeln('#           /     )_/        \          /')
        self.writeln('#                             \ ______ /')
        self.writeln('#                         SCANER PRIVAT')
        self.writeln('#             SCANER FOLOSIT DOAR DE TEAMUL zRRTEAM')
        self.writeln('#            SACNERUL CONTINE UN PASS_FLIE DE 3MEGA !!')
        self.writeln('####################################################################')
slist[6649] = command_start3

# f3511c928dbc381c0d7b35d63821ea01
class command_start_sh1(HoneyPotCommand):
    def call(self):
        self.writeln('Enjoy FloodBot based on OverKill')
slist[67] = command_start3

# 3c56bd3a394c1a842ec57226d8ee5d81
class command_go_sh1(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln('A must be between 1 and 254')
        else:
            self.writeln('scanning network %s.*' % self.args[0])
            self.writeln('usec: 30000, burst packets 50')
            self.writeln('using interface eth0')
            self.writeln('using "(tcp[tcpflags]=0x12) and (src port 22) and (dst port 15232)" as pcap filter')
            self.writeln('my detected ip on eth0 is 127.0.0.1')
            self.writeln('capturing process started pid 2259')
            # much more happens after this, but I'm lazy
        self.writeln('Toata \033[31mdragostea\033[0m mea pentru \033[32mdiavola\033[0m!!!!!!')
slist[92] = command_go_sh1
clist['go.sh'] = command_go_sh1

# 978cc6e3ce07787898519aa26f3b429c
# dc7b9585c47ab44830dc84a11e0272fe
class command_bash(HoneyPotCommand):
    def call(self):
        self.writeln('EnergyMech 2.9.3, May 16th, 2003')
        self.writeln('Compiled on Mar  4 2005 15:06:49')
        self.writeln('Features: DBG, LNE, SEE, LNK, TEL, PIP, DYN, ALS, SEF')
slist[492135] = command_bash # bash
slist[29] = command_bash # run
clist['bash'] = command_bash

# e41604f2449fb75eebbf5530ee3a8c2c
class command_a(HoneyPotCommand):
    def start(self):
        if not len(self.args):
            self.writeln(' usage: ./a <b class>')
            self.exit()
            return
        self.writeln('\033[1;31m\xAB\033[1;32m Created bY MaLa \033[1;31m\xBB\033[0m')
        self.writeln('INCERC SA DAU VIATZA CIBERNETICI')
        self.write('# scanning: %s (total: 0) (0.01%% done)' % self.args[0])
slist[1287] = command_a
clist['a'] = command_a

# b51a52c9c82bb4401659b4c17c60f89f
class command_ss(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln('usage: ./ss <port> [-a <a class> | -b <b class>] [-i <interface] [-s <speed>]')
            return
        self.writeln('usec: 1000000, burst packets 50')
        self.writeln('using "(tcp[tcpflags]=0x12) and (src port 22) and (dst port 38659)" as pcap filter')
        self.writeln('my detected ip on eth0 is 127.0.0.1')
        self.writeln('capturing process started pid 2282')
slist[453972] = command_ss
clist['ss'] = command_ss

# vim: set sw=4 et tw=0:
