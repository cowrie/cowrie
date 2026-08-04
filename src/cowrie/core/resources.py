# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: read primitives for bundled cowrie.data package resources
# ABOUTME: thin wrappers over importlib.resources for fixed-name bundled files

from __future__ import annotations

from contextlib import contextmanager
from importlib.resources import files
from typing import IO, TYPE_CHECKING

from cowrie import data

if TYPE_CHECKING:
    import sys
    from collections.abc import Generator

    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:
        from importlib.abc import Traversable


def _data_resource(*parts: str) -> Traversable:
    """Build a Traversable for cowrie.data/<parts> using chained joinpath."""
    resource: Traversable = files(data)
    for part in parts:
        resource = resource.joinpath(part)
    return resource


def read_data_bytes(*parts: str) -> bytes:
    """Read bundled cowrie.data/<parts> as bytes.

    Raises FileNotFoundError if the resource does not exist or is not a
    regular file (e.g. it resolves to a directory). Checking is_file() keeps
    the error consistent across platforms: opening a directory raises
    IsADirectoryError on POSIX but PermissionError on Windows.
    """
    resource = _data_resource(*parts)
    if not resource.is_file():
        raise FileNotFoundError(str(resource))
    return resource.read_bytes()


@contextmanager
def open_data_binary(*parts: str) -> Generator[IO[bytes], None, None]:
    """Open bundled cowrie.data/<parts> as a binary stream.

    Use for pickle.load, json.load, or anything that wants a file object.
    Raises FileNotFoundError if the resource does not exist or is not a
    regular file (e.g. it resolves to a directory); see read_data_bytes().
    """
    resource = _data_resource(*parts)
    if not resource.is_file():
        raise FileNotFoundError(str(resource))
    with resource.open("rb") as fh:
        yield fh
