# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
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

# Inspiration and code snippets used from:
# http://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P

from __future__ import annotations

from twisted.python import log

from cowrie.ssh_proxy.protocols import base_protocol
from cowrie.core.fingerprint import (
    generate_ja4,
    generate_ja4h,
    parse_tls_client_hello,
    parse_http_request,
)


class PortForward(base_protocol.BaseProtocol):
    def __init__(self, uuid, chan_name, ssh):
        super().__init__(uuid, chan_name, ssh)

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
                        signature_algorithms=tls_info["signature_algorithms"]
                    )
                    log.msg(
                        eventid="cowrie.direct-tcpip.ja4",
                        format="JA4 fingerprint for SSH proxy forwarded TLS: %(ja4)s",
                        ja4=ja4
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4 fingerprint in SSH proxy: {e}")

        # Check for HTTP request
        elif data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"HEAD "):
            http_info = parse_http_request(data)
            if http_info:
                try:
                    ja4h = generate_ja4h(
                        method=http_info["method"],
                        version=http_info["version"],
                        headers=http_info["headers"],
                        cookies=http_info["cookies"],
                        referer=http_info["referer"],
                        accept_language=http_info["accept_language"]
                    )
                    log.msg(
                        eventid="cowrie.direct-tcpip.ja4h",
                        format="JA4H fingerprint for SSH proxy forwarded HTTP: %(ja4h)s",
                        ja4h=ja4h
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4H fingerprint in SSH proxy: {e}")
