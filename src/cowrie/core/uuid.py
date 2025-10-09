# Copyright (c) 2025 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


from __future__ import annotations

import os
import uuid

from twisted.python import log

from cowrie.core.config import CowrieConfig


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
            log.msg(f"UUID read from file {uuidpath} is invalid: '{uuid_from_file}'")
        else:
            return uuid_from_file
    except FileNotFoundError:
        # First run
        pass
    except PermissionError as e:
        log.err(
            f"Permission denied when attempting to read uuid from {uuidpath}: {e!r}"
        )
    except OSError as e:
        # Catch other I/O errors (e.g., directory not found, device error)
        log.err(f"I/O error when reading uuid from {uuidpath}: {e!r}")

    new_uuid_str = str(create_uuid())

    try:
        os.makedirs(os.path.dirname(uuidpath), exist_ok=True)
        with open(uuidpath, "w", encoding="ascii") as f:
            f.write(f"{new_uuid_str}\n")
    except PermissionError as e:
        log.err(f"Permission denied when attempting to write uuid to {uuidpath}: {e!r}")
    except OSError as e:
        log.err(f"I/O error when writing uuid to {uuidpath}: {e!r}")

    return new_uuid_str
