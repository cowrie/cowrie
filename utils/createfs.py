#!/usr/bin/env python

import os, pickle, sys, locale
from stat import *

def recurse(root, tree, count = 0):
    A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, \
        A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(0, 10)
    T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(0, 7)

    for name in os.listdir(root):
        path = os.path.join(root, name)
        if path in (
                '/root/fs.pickle',
                '/root/createfs.py',
                '/root/.bash_history',
                ):
            continue

        try:
            if os.path.islink(path):
                s = os.lstat(path)
            else:
                s = os.stat(path)
        except OSError:
            continue

        entry = [name, T_FILE, s.st_uid, s.st_gid, s.st_size, s.st_mode, \
            int(s.st_ctime), [], None, None]

	if S_ISLNK(s[ST_MODE]):
	    entry[A_TYPE] = T_LINK
	    entry[A_TARGET] = os.path.realpath(path)
        elif S_ISDIR(s[ST_MODE]):
            entry[A_TYPE] = T_DIR
            if not path.startswith('/proc/'):
                recurse(path, entry[A_CONTENTS])
        elif S_ISREG(s[ST_MODE]):
            entry[A_TYPE] = T_FILE
        elif S_ISBLK(s[ST_MODE]):
            entry[A_TYPE] = T_BLK
        elif S_ISCHR(s[ST_MODE]):
            entry[A_TYPE] = T_CHR
        elif S_ISSOCK(s[ST_MODE]):
            entry[A_TYPE] = T_SOCK
        elif S_ISFIFO(s[ST_MODE]):
            entry[A_TYPE] = T_FIFO
        else:
            sys.stderr.write('We should handle %s' % path)
	    sys.exit(1)

        tree.append(entry)

if __name__ == '__main__':
    A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, \
        A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(0, 10)
    T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(0, 7)

    tree = ['/', T_DIR, 0, 0, 0, 0, 0, [], '']
    # change to / to recurse a whole server:
    recurse('/', tree[A_CONTENTS], tree[A_CONTENTS])

    sys.stderr.write('Doing stuff\n')

    print pickle.dumps(tree)
