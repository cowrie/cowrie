# SPDX-FileCopyrightText: 2025 Onder7994
# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
find command
"""

from __future__ import annotations

import fnmatch
import posixpath

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_CONTENTS, A_NAME, A_TYPE, T_DIR, T_FILE, T_LINK, Node

commands = {}


class Command_find(HoneyPotCommand):
    """
    find command
    """

    def start(self) -> None:
        self.maxdepth: int = 20
        self.name_pattern = None
        self.type_filter = None

        self.start_path = self.cwd

        idx = 0
        while idx < len(self.args):
            arg = self.args[idx]

            if arg == "-name":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-name`\n")
                    self.exit()
                    return
                self.name_pattern = self.args[idx]

            elif arg == "-type":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-type`\n")
                    self.exit()
                    return
                val = self.args[idx]
                if val in ("f", "d"):
                    self.type_filter = val
                else:
                    self.errorWrite("find: unknown argument to -type. Use 'f' or 'd'\n")
                    self.exit()
                    return

            elif arg == "-maxdepth":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-maxdepth`\n")
                    self.exit()
                    return
                try:
                    self.maxdepth = int(self.args[idx])
                except ValueError:
                    self.errorWrite("find: maxdepth must be an integer\n")
                    self.exit()
                    return

            elif not arg.startswith("-") and self.start_path == self.cwd:
                self.start_path = self.fs.resolve_path(arg, self.cwd)

            else:
                self.errorWrite(f"find: unknown argument '{arg}'\n")
                self.exit()
                return

            idx += 1

        start = self.fs.getfile(self.start_path, follow_symlinks=False)
        if start is not None:
            self.find_recursive(self.start_path, start, 0)
        self.exit()

    def find_recursive(self, path: str, node: Node, depth: int) -> None:
        """
        Walk the tree from node, which is the filesystem entry at path.
        Children are reached through the node itself, so the walk never
        looks up a path from / again.
        """
        if depth > self.maxdepth:
            return
        try:
            if self._match(path, node):
                self.write(f"{path}\n")

            # A link given as the start path is followed. Like GNU find's
            # default -P, links below it are listed but not followed.
            if depth == 0 and node[A_TYPE] == T_LINK:
                target = self.fs.getfile(path)
                if target is None:
                    return
                node = target

            if node[A_TYPE] == T_DIR:
                for child in node[A_CONTENTS]:
                    if child[A_NAME] in (".", ".."):
                        continue
                    full_path = posixpath.join(path, child[A_NAME])
                    self.find_recursive(full_path, child, depth + 1)
        except Exception as e:
            self.errorWrite(f"find: error accessing {path}: {e}\n")

    def _match(self, path: str, node: Node) -> bool:
        basename = posixpath.basename(path)

        if self.name_pattern and not fnmatch.fnmatch(basename, self.name_pattern):
            return False

        if self.type_filter == "f" and node[A_TYPE] != T_FILE:
            return False
        if self.type_filter == "d" and node[A_TYPE] != T_DIR:
            return False

        return True


commands["find"] = Command_find
commands["/bin/find"] = Command_find
