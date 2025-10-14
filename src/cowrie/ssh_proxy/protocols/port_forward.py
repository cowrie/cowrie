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
from cowrie.core.fingerprint import JA4Fingerprint, JA4HFingerprint
from typing import Optional
import struct


def parse_tls_client_hello(data: bytes) -> Optional[dict]:
    """
    Parse a TLS Client Hello packet and extract fields needed for JA4 fingerprinting.

    Returns a dict with: tls_version, ciphers, extensions, has_sni, alpn, signature_algorithms
    Returns None if parsing fails.
    """
    try:
        if len(data) < 43:  # Minimum Client Hello size
            return None

        # TLS Record header: type(1) + version(2) + length(2)
        record_type = data[0]
        if record_type != 0x16:  # Not a handshake
            return None

        record_version = struct.unpack('!H', data[1:3])[0]
        record_length = struct.unpack('!H', data[3:5])[0]

        # Handshake header: type(1) + length(3)
        handshake_type = data[5]
        if handshake_type != 0x01:  # Not Client Hello
            return None

        # Skip handshake length (3 bytes)
        offset = 9

        # Client Hello: version(2) + random(32) + session_id_length(1)
        if len(data) < offset + 35:
            return None

        tls_version = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2

        # Skip random (32 bytes)
        offset += 32

        # Session ID length + session ID
        session_id_length = data[offset]
        offset += 1 + session_id_length

        if len(data) < offset + 2:
            return None

        # Cipher suites
        cipher_suites_length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2

        if len(data) < offset + cipher_suites_length:
            return None

        ciphers = []
        for i in range(0, cipher_suites_length, 2):
            cipher = struct.unpack('!H', data[offset+i:offset+i+2])[0]
            ciphers.append(cipher)
        offset += cipher_suites_length

        # Compression methods
        if len(data) < offset + 1:
            return None
        compression_length = data[offset]
        offset += 1 + compression_length

        # Extensions
        if len(data) < offset + 2:
            return None

        extensions_length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2

        extensions = []
        has_sni = False
        alpn = None
        signature_algorithms = None

        ext_end = offset + extensions_length
        while offset < ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack('!H', data[offset:offset+2])[0]
            ext_length = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4

            if offset + ext_length > len(data):
                break

            extensions.append(ext_type)

            # Check for SNI (0x0000)
            if ext_type == 0x0000:
                has_sni = True

            # Extract ALPN (0x0010)
            elif ext_type == 0x0010 and ext_length > 2:
                alpn_length = struct.unpack('!H', data[offset:offset+2])[0]
                if alpn_length > 0 and offset + 2 + alpn_length <= len(data):
                    alpn_data = data[offset+2:offset+2+alpn_length]
                    # Parse first ALPN protocol
                    if len(alpn_data) > 1:
                        proto_length = alpn_data[0]
                        if proto_length > 0 and len(alpn_data) >= 1 + proto_length:
                            alpn = alpn_data[1:1+proto_length].decode('ascii', errors='ignore')

            # Extract signature algorithms (0x000d)
            elif ext_type == 0x000d and ext_length > 2:
                sig_alg_length = struct.unpack('!H', data[offset:offset+2])[0]
                if sig_alg_length > 0 and offset + 2 + sig_alg_length <= len(data):
                    signature_algorithms = []
                    for i in range(0, sig_alg_length, 2):
                        if offset + 2 + i + 2 <= len(data):
                            sig_alg = struct.unpack('!H', data[offset+2+i:offset+2+i+2])[0]
                            signature_algorithms.append(sig_alg)

            offset += ext_length

        return {
            'tls_version': tls_version,
            'ciphers': ciphers,
            'extensions': extensions,
            'has_sni': has_sni,
            'alpn': alpn,
            'signature_algorithms': signature_algorithms
        }

    except Exception as e:
        log.msg(f"Error parsing TLS Client Hello: {e}")
        return None


def parse_http_request(data: bytes) -> Optional[dict]:
    """
    Parse HTTP request headers for JA4H fingerprinting.

    Returns a dict with: method, version, headers, cookies, referer, accept_language
    Returns None if parsing fails.
    """
    try:
        # Decode as ASCII (HTTP headers must be ASCII)
        request_text = data.decode('ascii', errors='ignore')
        lines = request_text.split('\r\n')

        if len(lines) < 1:
            return None

        # Parse request line: METHOD /path HTTP/version
        request_line = lines[0].split()
        if len(request_line) < 3:
            return None

        method = request_line[0]
        version_str = request_line[2]

        # Extract version (HTTP/1.1 -> "1.1")
        if version_str.startswith('HTTP/'):
            version = version_str[5:]
        else:
            version = "1.1"

        # Parse headers
        headers = []
        cookies = None
        referer = None
        accept_language = None

        for line in lines[1:]:
            if not line or ':' not in line:
                continue

            header_name = line.split(':', 1)[0].strip()
            header_value = line.split(':', 1)[1].strip() if ':' in line else ''

            headers.append(header_name)

            # Extract specific headers
            if header_name.lower() == 'cookie':
                cookie_list = []
                for cookie in header_value.split(';'):
                    cookie_name = cookie.split('=')[0].strip()
                    if cookie_name:
                        cookie_list.append(cookie_name)
                cookies = cookie_list if cookie_list else None

            elif header_name.lower() == 'referer':
                referer = header_value

            elif header_name.lower() == 'accept-language':
                accept_language = header_value

        return {
            'method': method,
            'version': version,
            'headers': headers,
            'cookies': cookies,
            'referer': referer,
            'accept_language': accept_language
        }

    except Exception as e:
        log.msg(f"Error parsing HTTP request: {e}")
        return None


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
                    ja4 = JA4Fingerprint.generate(
                        tls_version=tls_info['tls_version'],
                        ciphers=tls_info['ciphers'],
                        extensions=tls_info['extensions'],
                        has_sni=tls_info['has_sni'],
                        alpn=tls_info['alpn'],
                        signature_algorithms=tls_info['signature_algorithms']
                    )
                    log.msg(
                        eventid="cowrie.direct-tcpip.ja4",
                        format="JA4 fingerprint for SSH proxy forwarded TLS: %(ja4)s",
                        ja4=ja4
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4 fingerprint in SSH proxy: {e}")

        # Check for HTTP request
        elif data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HEAD '):
            http_info = parse_http_request(data)
            if http_info:
                try:
                    ja4h = JA4HFingerprint.generate(
                        method=http_info['method'],
                        version=http_info['version'],
                        headers=http_info['headers'],
                        cookies=http_info['cookies'],
                        referer=http_info['referer'],
                        accept_language=http_info['accept_language']
                    )
                    log.msg(
                        eventid="cowrie.direct-tcpip.ja4h",
                        format="JA4H fingerprint for SSH proxy forwarded HTTP: %(ja4h)s",
                        ja4h=ja4h
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4H fingerprint in SSH proxy: {e}")
