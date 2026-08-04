# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.logger import Logger

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    _log = Logger()

    def __init__(self, realm: IRealm) -> None:
        from cowrie.core.config import CowrieConfig

        self._log.info("Initialized LLM backend server")
        # Get hostname from config or use default
        self.hostname = CowrieConfig.get("honeypot", "hostname", fallback="svr04")
        self._log.info(
            "LLM backend server using hostname: {hostname}", hostname=self.hostname
        )

        # We don't need a virtual filesystem for the LLM backend
        # The LLM will simulate all filesystem interactions
