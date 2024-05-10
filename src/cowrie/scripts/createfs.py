#!/usr/bin/env python

###############################################################
# This program creates a cowrie file system pickle file.
#
# This is meant to build a brand new filesystem.
# To edit the file structure, please use 'bin/fsctl'
#
##############################################################

import fnmatch
import getopt
import os
import pickle
import sys
from stat import (
    S_ISBLK,
    S_ISCHR,
    S_ISDIR,
    S_ISFIFO,
    S_ISLNK,
    S_ISREG,
    S_ISSOCK,
    ST_MODE,
)

(
    A_NAME,
    A_TYPE,
    A_UID,
    A_GID,
    A_SIZE,
    A_MODE,
    A_CTIME,
    A_CONTENTS,
    A_TARGET,
    A_REALFILE,
) = range(0, 10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(0, 7)
PROC = False
VERBOSE = False

blacklist_files = [
    "/root/fs.pickle",
    "/root/createfs",
    "*cowrie*",
    "*kippo*",
]


def logit(ftxt):
    if VERBOSE:
        sys.stderr.write(ftxt)


def checkblacklist(ftxt):
    for value in blacklist_files:
        if fnmatch.fnmatch(ftxt, value):
            return True
    return False


def recurse(localroot, root, tree, maxdepth=100):
    if maxdepth == 0:
        return

    localpath = os.path.join(localroot, root[1:])

    logit(f" {localpath}\n")

    if not os.access(localpath, os.R_OK):
        logit(f" Cannot access {localpath}\n")
        return

    for name in os.listdir(localpath):
        fspath = os.path.join(root, name)
        if checkblacklist(fspath):
            continue

        path = os.path.join(localpath, name)

        try:
            if os.path.islink(path):
                s = os.lstat(path)
            else:
                s = os.stat(path)
        except OSError:
            continue

        entry = [
            name,
            T_FILE,
            s.st_uid,
            s.st_gid,
            s.st_size,
            s.st_mode,
            int(s.st_mtime),
            [],
            None,
            None,
        ]

        if S_ISLNK(s[ST_MODE]):
            if not os.access(path, os.R_OK):
                logit(f" Cannot access link: {path}\n")
                continue
            realpath = os.path.realpath(path)
            if not realpath.startswith(localroot):
                logit(
                    f' Link "{path}" has real path "{realpath}" outside local root "{localroot}"\n'
                )
                continue
            else:
                entry[A_TYPE] = T_LINK
                entry[A_TARGET] = realpath[len(localroot) :]
        elif S_ISDIR(s[ST_MODE]):
            entry[A_TYPE] = T_DIR
            if (PROC or not localpath.startswith("/proc/")) and maxdepth > 0:
                recurse(localroot, fspath, entry[A_CONTENTS], maxdepth - 1)
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
            sys.stderr.write(f"We should handle {path}")
            sys.exit(1)

        tree.append(entry)


def help(brief=False):
    print(
        f"Usage: {os.path.basename(sys.argv[0])} [-h] [-v] [-p] [-l dir] [-d maxdepth] [-o file]\n"
    )

    if not brief:
        print("  -v             verbose")
        print("  -p             include /proc")
        print(
            "  -l <dir>       local root directory (default is current working directory)"
        )
        print("  -d <depth>     maximum depth (default is full depth)")
        print("  -o <file>      write output to file instead of stdout")
        print("  -h             display this help\n")

    sys.exit(1)


def run():
    maxdepth = 100
    localroot = os.getcwd()
    output = ""

    try:
        optlist, args = getopt.getopt(sys.argv[1:], "hvpl:d:o:", ["help"])
    except getopt.GetoptError as error:
        sys.stderr.write(f"Error: {error}\n")
        help()
        return

    for o, a in optlist:
        if o == "-v":
            pass
        elif o == "-p":
            pass
        elif o == "-l":
            localroot = a
        elif o == "-d":
            maxdepth = int(a)
        elif o == "-o":
            output = a
        elif o in ["-h", "--help"]:
            help()

    if output and os.path.isfile(output):
        sys.stderr.write(f"File: {output} exists!\n")
        sys.exit(1)

    logit("Processing:\n")

    tree = ["/", T_DIR, 0, 0, 0, 0, 0, [], ""]
    recurse(localroot, "/", tree[A_CONTENTS], maxdepth)

    if output:
        pickle.dump(tree, open(output, "wb"))
    else:
        print(pickle.dumps(tree))


if __name__ == "__main__":
    run()
