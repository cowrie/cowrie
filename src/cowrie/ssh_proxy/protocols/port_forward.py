# SPDX-FileCopyrightText: 2016 Thomas Nicholson <tnnich@googlemail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# Inspiration and code snippets used from:
# http://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P

from __future__ import annotations

from twisted.logger import Logger

from cowrie.core.fingerprint import (
    generate_ja4,
    generate_ja4h,
    parse_http_request,
    parse_tls_client_hello,
)
from cowrie.ssh_proxy.protocols import base_protocol


class PortForward(base_protocol.BaseProtocol):
    _log = Logger()

    def __init__(self, uuid, chan_name, ssh):
        super().__init__(uuid, chan_name, ssh)
        self.events = ssh.server.events

    def parse_packet(self, parent: str, data: bytes) -> None:
        """
        Parse forwarded traffic and generate JA4/JA4H fingerprints.
        """
        # Try to fingerprint the forwarded traffic

        # Check for TLS Client Hello (0x16 = Handshake, 0x01 = Client Hello)
        if len(data) >= 6 and data[0] == 0x16 and data[5] == 0x01:
            tls_info = parse_tls_client_hello(data)
            if tls_info:
                try:
                    ja4 = generate_ja4(
                        tls_version=tls_info["tls_version"],
                        ciphers=tls_info["ciphers"],
                        extensions=tls_info["extensions"],
                        has_sni=tls_info["has_sni"],
                        alpn=tls_info["alpn"],
                        signature_algorithms=tls_info["signature_algorithms"],
                    )
                    if self.events:
                        self.events.dispatch(
                            "cowrie.direct-tcpip.ja4",
                            "JA4 fingerprint for SSH proxy forwarded TLS: %(ja4)s",
                            ja4=ja4,
                        )
                except Exception as e:
                    self._log.info(
                        "Error generating JA4 fingerprint in SSH proxy: {error}",
                        error=e,
                    )

        # Check for HTTP request
        elif (
            data.startswith(b"GET ")
            or data.startswith(b"POST ")
            or data.startswith(b"HEAD ")
        ):
            http_info = parse_http_request(data)
            if http_info:
                try:
                    ja4h = generate_ja4h(
                        method=http_info["method"],
                        version=http_info["version"],
                        headers=http_info["headers"],
                        cookies=http_info["cookies"],
                        referer=http_info["referer"],
                        accept_language=http_info["accept_language"],
                    )
                    if self.events:
                        self.events.dispatch(
                            "cowrie.direct-tcpip.ja4h",
                            "JA4H fingerprint for SSH proxy forwarded HTTP: %(ja4h)s",
                            ja4h=ja4h,
                        )
                except Exception as e:
                    self._log.info(
                        "Error generating JA4H fingerprint in SSH proxy: {error}",
                        error=e,
                    )
