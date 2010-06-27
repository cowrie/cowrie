#!/usr/bin/env python

import anydbm, sys, os

if __name__ == '__main__':
    if len(sys.argv) < 3 or \
            (sys.argv[2] in ('add', 'remove') and len(sys.argv) < 4):
        print 'Usage: %s <pass.db> <add|remove|list> [password]' % \
            os.path.basename(sys.argv[0])
        sys.exit(1)
    db = anydbm.open(sys.argv[1], 'c')
    if sys.argv[2] == 'list':
        for password in db.keys():
            print password
    elif sys.argv[2] == 'add':
        db[sys.argv[3]] = None
    elif sys.argv[2] == 'remove':
        del db[sys.argv[3]]
    else:
        print 'Unknown option: %s' % (sys.argv[2],)
    db.close()

# vim: set ft=python sw=4 et:
