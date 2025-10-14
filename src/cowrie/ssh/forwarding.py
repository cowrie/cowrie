# Copyright (c) 2009-2014 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH direct-tcpip connection requests
"""

from __future__ import annotations

from twisted.conch.ssh import forwarding
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.core.fingerprint import JA4Fingerprint, JA4HFingerprint
import struct
from typing import Optional


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


def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    This function will redirect an SSH forward request to another address
    or will log the request and do nothing
    """
    remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)

    log.msg(
        eventid="cowrie.direct-tcpip.request",
        format="direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s",
        dst_ip=remoteHP[0],
        dst_port=remoteHP[1],
        src_ip=origHP[0],
        src_port=origHP[1],
    )

    # Forward redirect
    redirectEnabled: bool = CowrieConfig.getboolean(
        "ssh", "forward_redirect", fallback=False
    )
    if redirectEnabled:
        redirects = {}
        items = CowrieConfig.items("ssh")
        for i in items:
            if i[0].startswith("forward_redirect_"):
                destPort = i[0].split("_")[-1]
                redirectHP = i[1].split(":")
                redirects[int(destPort)] = (redirectHP[0], int(redirectHP[1]))
        if remoteHP[1] in redirects:
            remoteHPNew = redirects[remoteHP[1]]
            log.msg(
                eventid="cowrie.direct-tcpip.redirect",
                format="redirected direct-tcp connection request from %(src_ip)s:%(src_port)"
                + "d to %(dst_ip)s:%(dst_port)d to %(new_ip)s:%(new_port)d",
                new_ip=remoteHPNew[0],
                new_port=remoteHPNew[1],
                dst_ip=remoteHP[0],
                dst_port=remoteHP[1],
                src_ip=origHP[0],
                src_port=origHP[1],
            )
            return SSHConnectForwardingChannel(
                remoteHPNew, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
            )

    # TCP tunnel
    tunnelEnabled: bool = CowrieConfig.getboolean(
        "ssh", "forward_tunnel", fallback=False
    )
    if tunnelEnabled:
        tunnels = {}
        items = CowrieConfig.items("ssh")
        for i in items:
            if i[0].startswith("forward_tunnel_"):
                destPort = i[0].split("_")[-1]
                tunnelHP = i[1].split(":")
                tunnels[int(destPort)] = (tunnelHP[0], int(tunnelHP[1]))
        if remoteHP[1] in tunnels:
            remoteHPNew = tunnels[remoteHP[1]]
            log.msg(
                eventid="cowrie.direct-tcpip.tunnel",
                format="tunneled direct-tcp connection request %(src_ip)s:%(src_port)"
                + "d->%(dst_ip)s:%(dst_port)d to %(new_ip)s:%(new_port)d",
                new_ip=remoteHPNew[0],
                new_port=remoteHPNew[1],
                dst_ip=remoteHP[0],
                dst_port=remoteHP[1],
                src_ip=origHP[0],
                src_port=origHP[1],
            )
            return TCPTunnelForwardingChannel(
                remoteHPNew,
                remoteHP,
                remoteWindow=remoteWindow,
                remoteMaxPacket=remoteMaxPacket,
            )

    return FakeForwardingChannel(
        remoteHP, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
    )


class SSHConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This class modifies the original to close the connection
    """

    name = b"cowrie-forwarded-direct-tcpip"

    def eofReceived(self) -> None:
        self.loseConnection()


class FakeForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This channel does not forward, but just logs requests.
    """

    name = b"cowrie-discarded-direct-tcpip"

    def channelOpen(self, specificData: bytes) -> None:
        pass

    def dataReceived(self, data: bytes) -> None:
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
                        format="JA4 fingerprint for forwarded TLS to %(dst_ip)s:%(dst_port)s: %(ja4)s",
                        dst_ip=self.hostport[0],
                        dst_port=self.hostport[1],
                        ja4=ja4
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4 fingerprint: {e}")

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
                        format="JA4H fingerprint for forwarded HTTP to %(dst_ip)s:%(dst_port)s: %(ja4h)s",
                        dst_ip=self.hostport[0],
                        dst_port=self.hostport[1],
                        ja4h=ja4h
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4H fingerprint: {e}")

        log.msg(
            eventid="cowrie.direct-tcpip.data",
            format="discarded direct-tcp forward request %(id)s to %(dst_ip)s:%(dst_port)s with data %(data)s",
            dst_ip=self.hostport[0],
            dst_port=self.hostport[1],
            data=repr(data),
            id=self.id,
        )
        self._close("Connection refused")


class TCPTunnelForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This class modifies the original to perform TCP tunneling via the CONNECT method
    """

    name = b"cowrie-tunneled-direct-tcpip"

    def __init__(self, hostport, dstport, *args, **kw):
        """
        Modifies the original to store where the data was originally going to go
        """
        forwarding.SSHConnectForwardingChannel.__init__(self, hostport, *args, **kw)
        self.dstport = dstport
        self.tunnel_established = False

    def channelOpen(self, specificData: bytes) -> None:
        """
        Modifies the original to send a TCP tunnel request via the CONNECT method
        """
        forwarding.SSHConnectForwardingChannel.channelOpen(self, specificData)
        dst = self.dstport[0] + ":" + str(self.dstport[1])
        connect_hdr = b"CONNECT " + dst.encode("ascii") + b" HTTP/1.1\r\n\r\n"
        forwarding.SSHConnectForwardingChannel.dataReceived(self, connect_hdr)

    def dataReceived(self, data: bytes) -> None:
        # Try to fingerprint the tunneled traffic

        # Check for TLS Client Hello
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
                        format="JA4 fingerprint for tunneled TLS to %(dst_ip)s:%(dst_port)s: %(ja4)s",
                        dst_ip=self.dstport[0],
                        dst_port=self.dstport[1],
                        ja4=ja4
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4 fingerprint in tunnel: {e}")

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
                        format="JA4H fingerprint for tunneled HTTP to %(dst_ip)s:%(dst_port)s: %(ja4h)s",
                        dst_ip=self.dstport[0],
                        dst_port=self.dstport[1],
                        ja4h=ja4h
                    )
                except Exception as e:
                    log.msg(f"Error generating JA4H fingerprint in tunnel: {e}")

        log.msg(
            eventid="cowrie.tunnelproxy-tcpip.data",
            format="sending via tunnel proxy %(data)s",
            data=repr(data),
        )
        forwarding.SSHConnectForwardingChannel.dataReceived(self, data)

    def write(self, data: bytes) -> None:
        """
        Modifies the original to strip off the TCP tunnel response
        """
        if not self.tunnel_established and data[:4].lower() == b"http":
            # Check proxy response code
            try:
                res_code = int(data.split(b" ")[1], 10)
            except ValueError:
                log.err("Failed to parse TCP tunnel response code")
                self._close("Connection refused")
                return
            if res_code != 200:
                log.err(f"Unexpected response code: {res_code}")
                self._close("Connection refused")
            # Strip off rest of packet
            eop = data.find(b"\r\n\r\n")
            if eop > -1:
                data = data[eop + 4 :]
            # This only happens once when the channel is opened
            self.tunnel_established = True

        forwarding.SSHConnectForwardingChannel.write(self, data)

    def eofReceived(self) -> None:
        self.loseConnection()
