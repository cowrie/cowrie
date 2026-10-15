# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Guards the package layering: the ssh and telnet transports must not
# ABOUTME: import the emulated shell, which sits above them and imports them.

from __future__ import annotations

import ast
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]

# Transport packages and the package they must never import.
LAYERING = {
    ("ssh", "ssh_proxy", "telnet", "telnet_proxy"): "cowrie.shell",
}


def imported_modules(path: Path) -> list[tuple[int, str]]:
    """Every absolute module name imported anywhere in the file, including
    imports inside functions and TYPE_CHECKING blocks."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            # module.name also catches "from cowrie import shell".
            found.extend(
                (node.lineno, f"{node.module}.{alias.name}") for alias in node.names
            )
    return found


class ImportLayeringTests(unittest.TestCase):
    def test_transports_do_not_import_shell(self) -> None:
        for packages, forbidden in LAYERING.items():
            violations = [
                f"{path.relative_to(SRC.parent)}:{lineno} imports {name}"
                for package in packages
                for path in sorted((SRC / package).rglob("*.py"))
                for lineno, name in imported_modules(path)
                if name == forbidden or name.startswith(forbidden + ".")
            ]
            self.assertEqual(violations, [])
