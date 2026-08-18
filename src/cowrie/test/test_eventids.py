# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Conformance tests keeping the event id catalogue, the emitters,
# ABOUTME: the output plugins matching on ids, and docs/OUTPUT.rst in step.

from __future__ import annotations

import ast
import itertools
import pathlib
import re
import unittest

import cowrie
from cowrie.core.eventids import ALL

SOURCE_ROOT = pathlib.Path(cowrie.__file__).parent
DOCS = SOURCE_ROOT.parent.parent / "docs" / "OUTPUT.rst"

# The two pipeline stages that forward an already-built event instead of
# naming one: EventLog hands its event to the dispatcher, and an output
# plugin's dispatch() forwards the enrichment event it was given. Every
# other dispatch() call names its event id literally, which is what makes
# the emitted set knowable by reading the source.
FORWARDING_SITES = {"core/events.py", "core/output.py"}


def production_sources() -> list[pathlib.Path]:
    """Every module attackers' activity is observed in -- the test package
    emits synthetic ids of its own and is deliberately not scanned."""
    return [p for p in sorted(SOURCE_ROOT.rglob("*.py")) if "test" not in p.parts]


def string_constants(node: ast.AST) -> set[str]:
    return {
        n.value
        for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }


def event_ids_in(node: ast.AST) -> set[str]:
    return {s for s in string_constants(node) if s.startswith("cowrie.")}


def reads_eventid(node: ast.AST) -> bool:
    """Whether an expression reads an event's id, however it spells it:
    ``event["eventid"]``, a bare ``eventid`` local, or ``.eventid``."""
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and n.value == "eventid":
            return True
        if isinstance(n, ast.Name) and n.id == "eventid":
            return True
        if isinstance(n, ast.Attribute) and n.attr == "eventid":
            return True
    return False


class EventIdScanner(ast.NodeVisitor):
    """Collects the event ids a module emits and the ones it matches on."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.emitted: dict[str, str] = {}
        self.consumed: dict[str, str] = {}
        self.unnamed: list[str] = []

    def where(self, node: ast.AST) -> str:
        return f"{self.path}:{node.lineno}"  # type: ignore[attr-defined]

    def record(self, found: dict[str, str], ids: set[str], node: ast.AST) -> None:
        for eventid in ids:
            found.setdefault(eventid, self.where(node))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name == "dispatch":
            self.visit_dispatch(node)
        # An id tested by prefix: event["eventid"].startswith("cowrie.login")
        if isinstance(func, ast.Attribute) and func.attr in ("startswith", "endswith"):
            if reads_eventid(func.value):
                for arg in node.args:
                    self.record(self.consumed, event_ids_in(arg), node)
        self.generic_visit(node)

    def visit_dispatch(self, node: ast.Call) -> None:
        """An emitter names its event id as the first positional argument
        (EventLog.dispatch) or as an eventid keyword (Output.dispatch)."""
        named = None
        if node.args:
            named = node.args[0]
        else:
            for keyword in node.keywords:
                if keyword.arg == "eventid":
                    named = keyword.value
        if isinstance(named, ast.Constant) and isinstance(named.value, str):
            self.record(self.emitted, {named.value}, node)
        elif self.path not in FORWARDING_SITES:
            self.unnamed.append(self.where(node))

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        if any(reads_eventid(operand) for operand in operands):
            for operand in operands:
                self.record(self.consumed, event_ids_in(operand), node)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        if reads_eventid(node.subject):
            for case in node.cases:
                self.record(self.consumed, event_ids_in(case.pattern), case.pattern)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """A dispatch table keyed by event id, as slack builds."""
        keys = {
            key.value
            for key in node.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if node.keys and len(keys) == len(node.keys) and keys == event_ids_in(node):
            self.record(self.consumed, keys, node)
        self.generic_visit(node)


def scan() -> tuple[dict[str, str], dict[str, str], list[str]]:
    emitted: dict[str, str] = {}
    consumed: dict[str, str] = {}
    unnamed: list[str] = []
    for path in production_sources():
        relative = str(path.relative_to(SOURCE_ROOT))
        scanner = EventIdScanner(relative)
        scanner.visit(ast.parse(path.read_text(), str(path)))
        for eventid, site in scanner.emitted.items():
            emitted.setdefault(eventid, site)
        for eventid, site in scanner.consumed.items():
            consumed.setdefault(eventid, site)
        unnamed.extend(scanner.unnamed)
    return emitted, consumed, unnamed


def documented_ids() -> set[str]:
    """The event ids OUTPUT.rst has a section for."""
    lines = DOCS.read_text().splitlines()
    return {
        line.strip()
        for line, underline in itertools.pairwise(lines)
        if line.startswith("cowrie.") and re.fullmatch("=+", underline)
    }


class EventIdRegistryTests(unittest.TestCase):
    """Every event id in the tree is in the catalogue, and vice versa."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.emitted, cls.consumed, cls.unnamed = scan()

    def test_emitted_ids_are_registered(self) -> None:
        unregistered = {
            eventid: site
            for eventid, site in self.emitted.items()
            if eventid not in ALL
        }
        self.assertEqual(
            unregistered,
            {},
            "event ids emitted but missing from cowrie.core.eventids.ALL",
        )

    def test_registered_ids_are_emitted(self) -> None:
        """A catalogue entry no emitter produces is a stale id: consumers
        matching on it wait forever."""
        self.assertEqual(
            sorted(ALL - set(self.emitted)),
            [],
            "event ids in cowrie.core.eventids.ALL that nothing emits",
        )

    def test_consumed_ids_are_registered(self) -> None:
        """An output plugin matching on an id nothing emits is dead code --
        the failure mode is silent, so it is worth a test. A prefix such as
        ``cowrie.login`` is how abuseipdb matches a family of events."""
        prefixes = {eventid.rsplit(".", 1)[0] for eventid in ALL}
        unregistered = {
            eventid: site
            for eventid, site in self.consumed.items()
            if eventid not in ALL and eventid not in prefixes
        }
        self.assertEqual(
            unregistered,
            {},
            "event ids matched on that no emitter produces",
        )

    def test_emitters_name_their_event_id(self) -> None:
        """An event id assembled at runtime would be invisible to this
        catalogue, so emitters spell theirs out."""
        self.assertEqual(
            self.unnamed,
            [],
            "dispatch() calls that do not name their event id literally",
        )

    @unittest.skipUnless(DOCS.exists(), "docs are not part of an installed package")
    def test_docs_document_the_registry(self) -> None:
        documented = documented_ids()
        self.assertEqual(
            sorted(ALL - documented),
            [],
            "event ids missing a section in docs/OUTPUT.rst",
        )
        self.assertEqual(
            sorted(documented - ALL),
            [],
            "docs/OUTPUT.rst sections for event ids that are not in the registry",
        )
