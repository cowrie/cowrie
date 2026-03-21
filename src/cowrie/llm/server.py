# Copyright (C) 2024 Michel Oosterhof <michel@oosterhof.net>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.python import log

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    def __init__(self, realm: IRealm) -> None:
        from cowrie.core.config import CowrieConfig

        log.msg("Initialized LLM backend server")
        # Get hostname from config or use default
        self.hostname = CowrieConfig.get("honeypot", "hostname", fallback="svr04")
        log.msg(f"LLM backend server using hostname: {self.hostname}")

        # We don't need a virtual filesystem for the LLM backend
        # The LLM will simulate all filesystem interactions
