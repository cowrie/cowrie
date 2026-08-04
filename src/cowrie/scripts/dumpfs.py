#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Stefan Grosser
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Dump a cowrie fs.pickle as sorted, tab-separated lines for review/diff.
# ABOUTME: Format is path, type, mode, uid:gid, size, target; mtime is omitted so
# ABOUTME: two rebuilds of the same image diff cleanly.
#
# Usage:
#     dumpfs src/cowrie/data/fs.pickle
#     diff <(dumpfs --paths src/cowrie/data/fs.pickle) <(dumpfs --paths src/cowrie/data/fs.pickle.new)
#     dumpfs --paths src/cowrie/data/fs.pickle   # path set only
#
# Loads pickle data: only run on pickles you produced or trust.

from __future__ import annotations

import argparse
import pickle
import signal
import sys
from typing import Any

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

TYPES = ["LNK", "DIR", "REG", "BLK", "CHR", "SOCK", "FIFO"]
T_DIR = 1


def walk(node: list[Any], parent: str, paths_only: bool, out: list[str]) -> None:
    # Older pickles have 9 fields (no realfile); newer createfs.py writes 10.
    name, typ, uid, gid, size, mode, _mtime, kids, target = node[:9]
    path = "/" if name == "/" else f"{parent}/{name}"
    if paths_only:
        out.append(f"{path}\n")
    else:
        out.append(
            f"{path}\t{TYPES[typ]}\t{mode:o}\t{uid}:{gid}\t{size}\t{target or ''}\n"
        )
    if typ == T_DIR:
        child_parent = "" if path == "/" else path
        for child in kids:
            walk(child, child_parent, paths_only, out)


def run() -> None:
    ap = argparse.ArgumentParser(description="Dump a cowrie fs.pickle for review.")
    ap.add_argument("pickle", help="path to fs.pickle")
    ap.add_argument("--paths", action="store_true", help="emit only the path list")
    args = ap.parse_args()

    with open(args.pickle, "rb") as fh:
        tree = pickle.load(fh)

    lines: list[str] = []
    walk(tree, "", args.paths, lines)
    lines.sort()
    sys.stdout.writelines(lines)


if __name__ == "__main__":
    run()
