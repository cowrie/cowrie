#!/usr/bin/env python3
# Dump a cowrie fs.pickle as sorted, tab-separated lines for review/diff.
#
# Format: path<TAB>type<TAB>mode<TAB>uid:gid<TAB>size<TAB>target
# mtime is omitted so two rebuilds of the same image diff cleanly.
#
# Usage:
#     bin/dump-fs-pickle.py src/cowrie/data/fs.pickle
#     diff <(bin/dump-fs-pickle.py --paths src/cowrie/data/fs.pickle) <(bin/dump-fs-pickle.py --paths src/cowrie/data/fs.pickle.new)
#     bin/dump-fs-pickle.py --paths src/cowrie/data/fs.pickle   # path set only

import argparse
import pickle
import signal
import sys

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

TYPES = ["LNK", "DIR", "REG", "BLK", "CHR", "SOCK", "FIFO"]
T_DIR = 1


def walk(node, parent, paths_only, out):
    # Older pickles have 9 fields (no realfile); newer createfs.py writes 10.
    name, typ, uid, gid, size, mode, _mtime, kids, target = node[:9]
    path = "/" if name == "/" else f"{parent}/{name}"
    if paths_only:
        out.write(f"{path}\n")
    else:
        out.write(
            f"{path}\t{TYPES[typ]}\t{oct(mode)}\t{uid}:{gid}\t{size}\t{target or ''}\n"
        )
    if typ == T_DIR:
        for child in sorted(kids, key=lambda x: x[0]):
            walk(child, "" if path == "/" else path, paths_only, out)


def main():
    ap = argparse.ArgumentParser(description="Dump a cowrie fs.pickle for review.")
    ap.add_argument("pickle", help="path to fs.pickle")
    ap.add_argument("--paths", action="store_true", help="emit only the path list")
    args = ap.parse_args()

    with open(args.pickle, "rb") as fh:
        tree = pickle.load(fh)

    lines = []

    class _L:
        def write(self, s):
            lines.append(s)

    walk(tree, "", args.paths, _L())
    lines.sort()
    sys.stdout.writelines(lines)


if __name__ == "__main__":
    main()
