# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: pickle-backed honeyfs — load fs.pickle once, share tree and file contents
# ABOUTME: with HoneyPotFilesystem and with cowrie's internal banner/passwd/group readers

from __future__ import annotations

import configparser
import copy
import functools
import pickle
from pathlib import Path
from typing import Any

from cowrie.core.config import CowrieConfig
from cowrie.core.resources import open_data_binary

# Mirror of the entry-tuple field indices defined in cowrie.shell.fs.
# Duplicated here to avoid a circular import (fs imports get_tree from
# this module). Keep in sync.
A_NAME = 0
A_TYPE = 1
A_CONTENTS = 7
A_TARGET = 8
T_LINK = 0
T_DIR = 1
T_FILE = 2

# Cap on how many T_LINK hops we follow before declaring a loop.
_MAX_SYMLINK_DEPTH = 16


def _find(
    tree: list[Any], virtual_path: str, _depth: int = 0
) -> list[Any] | None:
    """Walk the cached tree to find the entry at virtual_path.

    Follows T_LINK entries (both intermediate and terminal) up to a
    fixed depth, treating link targets as absolute paths from the tree
    root. Returns None for missing paths, broken links, or symlink loops.
    """
    if _depth > _MAX_SYMLINK_DEPTH:
        return None

    parts = [p for p in virtual_path.split("/") if p]
    node: list[Any] = tree
    for part in parts:
        if node[A_TYPE] == T_LINK:
            resolved = _find(tree, node[A_TARGET], _depth + 1)
            if resolved is None:
                return None
            node = resolved
        children = node[A_CONTENTS]
        if not isinstance(children, list):
            return None
        match = next((c for c in children if c[A_NAME] == part), None)
        if match is None:
            return None
        node = match

    if node[A_TYPE] == T_LINK:
        return _find(tree, node[A_TARGET], _depth + 1)
    return node


@functools.cache
def _tree() -> list[Any]:
    """Load the filesystem pickle once and cache it for the process lifetime.

    Resolution:
      1. If [shell] filesystem is set, load that file.
      2. Otherwise, load the bundled fs.pickle from cowrie.data.

    Falls back to encoding='utf8' on UnicodeDecodeError to handle pickles
    produced under Python 2's str/bytes model.
    """
    try:
        filesystem = CowrieConfig.get("shell", "filesystem")
    except configparser.Error:
        filesystem = ""

    def _open():
        if filesystem:
            return open(filesystem, "rb")
        return open_data_binary("fs.pickle")

    try:
        with _open() as f:
            tree: list[Any] = pickle.load(f)
    except UnicodeDecodeError:
        with _open() as f:
            tree = pickle.load(f, encoding="utf8")
    return tree


def get_tree() -> list[Any]:
    """Return a fresh deep copy of the cached filesystem tree.

    Each HoneyPotFilesystem instance gets its own copy so per-session
    mutations (mkfile, init_honeyfs A_REALFILE markers, etc.) don't leak
    across sessions.
    """
    return copy.deepcopy(_tree())


def read_file(virtual_path: str) -> bytes:
    """Extract the embedded bytes for a regular file at virtual_path.

    Raises FileNotFoundError if the path doesn't exist in the tree, isn't a
    regular file, or has no embedded contents (A_CONTENTS not bytes).
    """
    node = _find(_tree(), virtual_path)
    if node is None or node[A_TYPE] != T_FILE:
        raise FileNotFoundError(virtual_path)
    contents = node[A_CONTENTS]
    if not isinstance(contents, bytes):
        raise FileNotFoundError(virtual_path)
    return contents


def read_honeyfs_bytes(relpath: str) -> bytes:
    """Read a honeyfs file with operator-override cascade.

    Resolution:
      1. If [honeypot] contents_path is set and <contents_path>/<relpath>
         is a regular file, return its bytes.
      2. Else, extract embedded bytes from the bundled pickle via read_file.
      3. If neither produces bytes, FileNotFoundError propagates.
    """
    try:
        contents_path = CowrieConfig.get("honeypot", "contents_path")
    except configparser.Error:
        contents_path = ""

    if contents_path:
        operator_path = Path(contents_path) / relpath
        if operator_path.is_file():
            return operator_path.read_bytes()

    return read_file("/" + relpath)
