#!/usr/bin/env python

import os

f = os.getcwd()
print f
n = os.system("./cowrie stop")
#n = os.system("twistd cowrie start")
print n
