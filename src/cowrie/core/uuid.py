# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import os
import uuid

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig

_log = Logger()


def create_uuid() -> uuid.UUID:
    """
    Generates a UUID Version 1 (time-based).

    Returns:
        A uuid.UUID object.
    """
    return uuid.uuid1()


def get_uuid() -> str:
    """
    Retrieve UUID from state file or create and persist a new one.

    Ensures the returned UUID is always a valid string representation.
    """
    state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
    uuidpath = os.path.join(state_path, "uuid")

    try:
        with open(uuidpath, encoding="ascii") as f:
            uuid_from_file = f.read().strip()

        # Validation: Check if the read content is a valid UUID before returning
        try:
            uuid.UUID(uuid_from_file)  # Will raise ValueError if invalid format
        except ValueError:
            _log.info(
                "UUID read from file {uuidpath} is invalid: '{uuid_from_file}'",
                uuidpath=uuidpath,
                uuid_from_file=uuid_from_file,
            )
        else:
            return uuid_from_file
    except FileNotFoundError:
        # First run
        pass
    except PermissionError:
        _log.failure(
            "Permission denied when attempting to read uuid from {uuidpath}",
            uuidpath=uuidpath,
        )
    except OSError:
        # Catch other I/O errors (e.g., directory not found, device error)
        _log.failure("I/O error when reading uuid from {uuidpath}", uuidpath=uuidpath)

    new_uuid_str = str(create_uuid())

    try:
        os.makedirs(os.path.dirname(uuidpath), exist_ok=True)
        with open(uuidpath, "w", encoding="ascii") as f:
            f.write(f"{new_uuid_str}\n")
    except PermissionError:
        _log.failure(
            "Permission denied when attempting to write uuid to {uuidpath}",
            uuidpath=uuidpath,
        )
    except OSError:
        _log.failure("I/O error when writing uuid to {uuidpath}", uuidpath=uuidpath)

    return new_uuid_str
