# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: read helpers for bundled cowrie.data resources and operator-overridable honeyfs files
# ABOUTME: centralises the operator-override-to-bundled cascade used at multiple call sites

from __future__ import annotations

import configparser
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from typing import IO, TYPE_CHECKING

from cowrie import data
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Generator
    from importlib.resources.abc import Traversable  # ty: ignore[unresolved-import]


def _data_resource(*parts: str) -> Traversable:
    """Build a Traversable for cowrie.data/<parts> using chained joinpath."""
    resource: Traversable = files(data)
    for part in parts:
        resource = resource.joinpath(part)
    return resource


def read_data_bytes(*parts: str) -> bytes:
    """Read bundled cowrie.data/<parts> as bytes.

    Raises FileNotFoundError if the resource does not exist.
    """
    return _data_resource(*parts).read_bytes()


@contextmanager
def open_data_binary(*parts: str) -> Generator[IO[bytes], None, None]:
    """Open bundled cowrie.data/<parts> as a binary stream.

    Use for pickle.load, json.load, or anything that wants a file object.
    Raises FileNotFoundError if the resource does not exist.
    """
    with _data_resource(*parts).open("rb") as fh:
        yield fh


def read_honeyfs_bytes(relpath: str) -> bytes:
    """Read a honeyfs file with operator-override cascade.

    Resolution:
      1. If [honeypot] contents_path is set and <contents_path>/<relpath>
         is a regular file, return its bytes.
      2. Else, return bytes of bundled cowrie.data/honeyfs/<relpath>.
      3. If neither exists, FileNotFoundError propagates.

    Note: in git-repo mode src/cowrie/data/honeyfs/ does not yet exist, so
    step 2 raises until honeyfs is moved into the package. The contract is
    stable; only the bundled side becomes populated later.
    """
    try:
        contents_path = CowrieConfig.get("honeypot", "contents_path")
    except (configparser.NoOptionError, configparser.NoSectionError):
        contents_path = ""

    if contents_path:
        operator_path = Path(contents_path) / relpath
        if operator_path.is_file():
            return operator_path.read_bytes()

    return read_data_bytes("honeyfs", *relpath.split("/"))
