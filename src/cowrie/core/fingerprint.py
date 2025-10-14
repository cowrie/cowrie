# ABOUTME: JA4+ fingerprinting functions for network traffic analysis
# ABOUTME: Provides JA4, JA4S, JA4H, JA4TCP, and JA4SSH fingerprinting capabilities

# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1.
#
# Adapted for Cowrie honeypot by Michel Oosterhof

"""
JA4+ Fingerprinting Module

This module provides network fingerprinting capabilities based on the JA4+ suite
developed by FoxIO. It includes:

- JA4: TLS client fingerprinting
- JA4S: TLS server fingerprinting
- JA4H: HTTP client fingerprinting
- JA4TCP: TCP connection fingerprinting
- JA4SSH: SSH client fingerprinting

These fingerprints help identify and track network clients based on their
protocol implementations and behavior patterns.
"""

from __future__ import annotations

from typing import Any
import socket
import struct

from twisted.python import log

from cowrie.vendor.ja4.common import sha_encode, GREASE_TABLE, TLS_MAPPER


# Convert FoxIO's string-based GREASE table to integer set for our use
GREASE_VALUES = {int(k, 16) for k in GREASE_TABLE.keys()}

# Convert FoxIO's string-based TLS mapper to integer keys
TLS_VERSION_MAP = {int(k, 16): v for k, v in TLS_MAPPER.items()}


def parse_tls_client_hello(data: bytes) -> dict | None:
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

        struct.unpack("!H", data[1:3])[0]
        struct.unpack("!H", data[3:5])[0]

        # Handshake header: type(1) + length(3)
        handshake_type = data[5]
        if handshake_type != 0x01:  # Not Client Hello
            return None

        # Skip handshake length (3 bytes)
        offset = 9

        # Client Hello: version(2) + random(32) + session_id_length(1)
        if len(data) < offset + 35:
            return None

        tls_version = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        # Skip random (32 bytes)
        offset += 32

        # Session ID length + session ID
        session_id_length = data[offset]
        offset += 1 + session_id_length

        if len(data) < offset + 2:
            return None

        # Cipher suites
        cipher_suites_length = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        if len(data) < offset + cipher_suites_length:
            return None

        ciphers = []
        for i in range(0, cipher_suites_length, 2):
            cipher = struct.unpack("!H", data[offset + i : offset + i + 2])[0]
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

        extensions_length = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        extensions = []
        has_sni = False
        alpn = None
        signature_algorithms = None

        ext_end = offset + extensions_length
        while offset < ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack("!H", data[offset : offset + 2])[0]
            ext_length = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4

            if offset + ext_length > len(data):
                break

            extensions.append(ext_type)

            # Check for SNI (0x0000)
            if ext_type == 0x0000:
                has_sni = True

            # Extract ALPN (0x0010)
            elif ext_type == 0x0010 and ext_length > 2:
                alpn_length = struct.unpack("!H", data[offset : offset + 2])[0]
                if alpn_length > 0 and offset + 2 + alpn_length <= len(data):
                    alpn_data = data[offset + 2 : offset + 2 + alpn_length]
                    # Parse first ALPN protocol
                    if len(alpn_data) > 1:
                        proto_length = alpn_data[0]
                        if proto_length > 0 and len(alpn_data) >= 1 + proto_length:
                            alpn = alpn_data[1 : 1 + proto_length].decode(
                                "ascii", errors="ignore"
                            )

            # Extract signature algorithms (0x000d)
            elif ext_type == 0x000D and ext_length > 2:
                sig_alg_length = struct.unpack("!H", data[offset : offset + 2])[0]
                if sig_alg_length > 0 and offset + 2 + sig_alg_length <= len(data):
                    signature_algorithms = []
                    for i in range(0, sig_alg_length, 2):
                        if offset + 2 + i + 2 <= len(data):
                            sig_alg = struct.unpack(
                                "!H", data[offset + 2 + i : offset + 2 + i + 2]
                            )[0]
                            signature_algorithms.append(sig_alg)

            offset += ext_length

        return {
            "tls_version": tls_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "has_sni": has_sni,
            "alpn": alpn,
            "signature_algorithms": signature_algorithms,
        }

    except Exception as e:
        log.msg(f"Error parsing TLS Client Hello: {e}")
        return None


def parse_http_request(data: bytes) -> dict | None:
    """
    Parse HTTP request headers for JA4H fingerprinting.

    Returns a dict with: method, version, headers, cookies, referer, accept_language
    Returns None if parsing fails.
    """
    try:
        # Decode as ASCII (HTTP headers must be ASCII)
        request_text = data.decode("ascii", errors="ignore")
        lines = request_text.split("\r\n")

        if len(lines) < 1:
            return None

        # Parse request line: METHOD /path HTTP/version
        request_line = lines[0].split()
        if len(request_line) < 3:
            return None

        method = request_line[0]
        version_str = request_line[2]

        # Extract version (HTTP/1.1 -> "1.1")
        if version_str.startswith("HTTP/"):
            version = version_str[5:]
        else:
            version = "1.1"

        # Parse headers
        headers = []
        cookies = None
        referer = None
        accept_language = None

        for line in lines[1:]:
            if not line or ":" not in line:
                continue

            header_name = line.split(":", 1)[0].strip()
            header_value = line.split(":", 1)[1].strip() if ":" in line else ""

            headers.append(header_name)

            # Extract specific headers
            if header_name.lower() == "cookie":
                cookie_list = []
                for cookie in header_value.split(";"):
                    cookie_name = cookie.split("=")[0].strip()
                    if cookie_name:
                        cookie_list.append(cookie_name)
                cookies = cookie_list if cookie_list else None

            elif header_name.lower() == "referer":
                referer = header_value

            elif header_name.lower() == "accept-language":
                accept_language = header_value

        return {
            "method": method,
            "version": version,
            "headers": headers,
            "cookies": cookies,
            "referer": referer,
            "accept_language": accept_language,
        }

    except Exception as e:
        log.msg(f"Error parsing HTTP request: {e}")
        return None


def calculate_ttl_hops(ttl: int) -> int:
    """
    Calculate the number of network hops based on TTL.

    Common initial TTL values:
    - 64 for Linux/Unix
    - 128 for Windows
    - 255 for network equipment

    Args:
        ttl: The observed Time To Live value

    Returns:
        Number of hops from source
    """
    if ttl <= 64:
        initial_ttl = 64
    elif ttl <= 128:
        initial_ttl = 128
    else:
        initial_ttl = 255
    return initial_ttl - ttl


class JA4TCPFingerprint:
    """
    Generate JA4TCP fingerprints from TCP connection details.

    JA4TCP captures TCP-level characteristics including window size,
    TTL, and other TCP options to fingerprint the client operating system
    and network stack.
    """

    def __init__(self, transport: Any):
        """
        Initialize JA4TCP fingerprinting from a Twisted transport.

        Args:
            transport: Twisted transport object with socket access
        """
        self.transport = transport
        self.ttl: int | None = None
        self.window_size: int | None = None
        self.tcp_options: list[int] = []

    def get_tcp_info(self) -> dict[str, Any]:
        """
        Extract TCP connection information from the socket.

        Returns:
            Dictionary containing TCP parameters
        """
        info = {}

        try:
            sock = self.transport.socket

            # Try to get TTL (Linux-specific)
            try:
                # IP_TTL = 2
                ttl_data = sock.getsockopt(socket.IPPROTO_IP, 2)
                self.ttl = (
                    struct.unpack("i", ttl_data)[0]
                    if isinstance(ttl_data, bytes)
                    else ttl_data
                )
                info["ttl"] = self.ttl
            except (OSError, AttributeError) as e:
                log.msg(f"Could not retrieve TTL: {e}")

            # Try to get window size
            try:
                # TCP_INFO = 11 on Linux
                if hasattr(socket, "TCP_INFO"):
                    tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                    # Window size is at different offsets depending on platform
                    # This is a simplified extraction
                    if len(tcp_info) >= 8:
                        # Parse basic TCP_INFO structure (Linux)
                        # This is platform-specific and may not work everywhere
                        pass
            except (OSError, AttributeError) as e:
                log.msg(f"Could not retrieve TCP window info: {e}")

        except Exception as e:
            log.msg(f"Error extracting TCP info: {e}")

        return info

    def generate(self) -> str | None:
        """
        Generate the JA4TCP fingerprint.

        Format: ttl_windowsize_options

        Returns:
            JA4TCP fingerprint string, or None if insufficient data
        """
        info = self.get_tcp_info()

        if not info:
            # Return a minimal fingerprint with just peer information
            try:
                peer = self.transport.getPeer()
                return f"unknown_{peer.host}_{peer.port}"
            except Exception:
                return None

        # Build fingerprint from available information
        parts = []

        if "ttl" in info:
            parts.append(str(info["ttl"]))
        else:
            parts.append("unknown")

        if "window_size" in info:
            parts.append(str(info["window_size"]))
        else:
            parts.append("unknown")

        # TCP options would go here if we could extract them
        parts.append("unknown")

        return "_".join(parts)


class JA4SSHFingerprint:
    """
    Generate JA4SSH fingerprints from SSH protocol exchanges.

    JA4SSH is similar to HASSH but follows the JA4 format conventions.
    It fingerprints the SSH client based on key exchange algorithms,
    encryption ciphers, MAC algorithms, and compression methods.
    """

    @staticmethod
    def generate(
        kex_algorithms: list[str],
        encryption_algorithms: list[str],
        mac_algorithms: list[str],
        compression_algorithms: list[str],
    ) -> str:
        """
        Generate JA4SSH fingerprint from SSH algorithm lists.

        Args:
            kex_algorithms: Key exchange algorithms
            encryption_algorithms: Encryption ciphers
            mac_algorithms: MAC algorithms
            compression_algorithms: Compression methods

        Returns:
            JA4SSH fingerprint string
        """
        # Count of each algorithm type
        kex_count = len(kex_algorithms)
        enc_count = len(encryption_algorithms)
        mac_count = len(mac_algorithms)
        comp_count = len(compression_algorithms)

        # Create hashes of the algorithm lists
        kex_hash = sha_encode(kex_algorithms)
        enc_hash = sha_encode(encryption_algorithms)
        mac_hash = sha_encode(mac_algorithms)

        # Format: c{kex_count}s{enc_count}m{mac_count}c{comp_count}_{kex_hash}_{enc_hash}_{mac_hash}
        return f"c{kex_count}e{enc_count}m{mac_count}c{comp_count}_{kex_hash}_{enc_hash}_{mac_hash}"


class JA4Fingerprint:
    """
    Generate JA4 fingerprints from TLS Client Hello messages.

    JA4 captures TLS client characteristics including version, SNI,
    ciphers, and extensions to create a unique fingerprint.
    """

    @staticmethod
    def generate(
        tls_version: int,
        ciphers: list[int],
        extensions: list[int],
        has_sni: bool = False,
        alpn: str | None = None,
        signature_algorithms: list[int] | None = None,
        use_quic: bool = False,
    ) -> str:
        """
        Generate JA4 fingerprint from TLS Client Hello.

        Args:
            tls_version: TLS version number
            ciphers: List of cipher suite values
            extensions: List of extension type values
            has_sni: Whether SNI extension is present
            alpn: ALPN protocol string
            signature_algorithms: Signature algorithm list
            use_quic: Whether this is QUIC (vs TCP)

        Returns:
            JA4 fingerprint string
        """
        # Protocol type
        ptype = "q" if use_quic else "t"

        # TLS version
        version = TLS_VERSION_MAP.get(tls_version, "00")

        # SNI indicator
        sni = "d" if has_sni else "i"

        # Filter out GREASE values from ciphers and extensions
        filtered_ciphers = [c for c in ciphers if c not in GREASE_VALUES]
        filtered_extensions = [e for e in extensions if e not in GREASE_VALUES]

        # Counts (max 99)
        cipher_count = min(len(filtered_ciphers), 99)
        ext_count = min(len(filtered_extensions), 99)

        # ALPN
        if alpn and len(alpn) > 2:
            alpn_value = f"{alpn[0]}{alpn[-1]}"
        elif alpn:
            alpn_value = alpn
        else:
            alpn_value = "00"

        # Create sorted cipher hash
        sorted_ciphers = sorted([f"{c:04x}" for c in filtered_ciphers])
        cipher_hash = sha_encode(sorted_ciphers) if sorted_ciphers else "000000000000"

        # Create sorted extension hash (with signature algorithms if present)
        sorted_extensions = sorted([f"{e:04x}" for e in filtered_extensions])
        if signature_algorithms:
            sig_alg_strs = [f"{s:04x}" for s in signature_algorithms]
            ext_string = ",".join(sorted_extensions) + "_" + ",".join(sig_alg_strs)
        else:
            ext_string = ",".join(sorted_extensions)
        ext_hash = sha_encode(ext_string) if sorted_extensions else "000000000000"

        # Format: {ptype}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
        return f"{ptype}{version}{sni}{cipher_count:02d}{ext_count:02d}{alpn_value}_{cipher_hash}_{ext_hash}"


class JA4SFingerprint:
    """
    Generate JA4S fingerprints from TLS Server Hello messages.

    JA4S captures TLS server characteristics to fingerprint the
    server's TLS implementation.
    """

    @staticmethod
    def generate(
        tls_version: int,
        cipher: int,
        extensions: list[int],
        alpn: str | None = None,
        use_quic: bool = False,
    ) -> str:
        """
        Generate JA4S fingerprint from TLS Server Hello.

        Args:
            tls_version: TLS version number
            cipher: Selected cipher suite
            extensions: List of extension type values
            alpn: ALPN protocol string
            use_quic: Whether this is QUIC (vs TCP)

        Returns:
            JA4S fingerprint string
        """
        # Protocol type
        ptype = "q" if use_quic else "t"

        # TLS version
        version = TLS_VERSION_MAP.get(tls_version, "00")

        # Extension count (max 99)
        ext_count = min(len(extensions), 99)

        # ALPN
        if alpn and len(alpn) > 2:
            alpn_value = f"{alpn[0]}{alpn[-1]}"
        elif alpn:
            alpn_value = alpn
        else:
            alpn_value = "00"

        # Cipher (without GREASE filtering for server)
        cipher_str = f"{cipher:04x}"

        # Create extension hash (in order, not sorted)
        ext_strings = [f"{e:04x}" for e in extensions]
        ext_hash = sha_encode(ext_strings) if ext_strings else "000000000000"

        # Format: {ptype}{version}{ext_count}{alpn}_{cipher}_{ext_hash}
        return f"{ptype}{version}{ext_count:02d}{alpn_value}_{cipher_str}_{ext_hash}"


class JA4HFingerprint:
    """
    Generate JA4H fingerprints from HTTP requests.

    JA4H captures HTTP client characteristics including method,
    version, headers, and cookies.
    """

    @staticmethod
    def generate(
        method: str,
        version: str,
        headers: list[str],
        cookies: list[str] | None = None,
        referer: str | None = None,
        accept_language: str | None = None,
    ) -> str:
        """
        Generate JA4H fingerprint from HTTP request using FoxIO's logic.

        Args:
            method: HTTP method (GET, POST, etc)
            version: HTTP version (1.0, 1.1, 2.0)
            headers: List of header names in order
            cookies: List of cookie names
            referer: Referer header presence
            accept_language: Accept-Language value

        Returns:
            JA4H fingerprint string
        """
        # Method (first 2 chars, lowercase) - from FoxIO ja4h.py
        method_str = method.lower()[:2]

        # Version - from FoxIO ja4h.py logic
        if version == "2.0":
            ver_str = "20"
        elif version == "1.1":
            ver_str = "11"
        elif version == "1.0":
            ver_str = "10"
        else:
            ver_str = "11"  # Default to 1.1

        # Filter headers (remove cookie, referer) and count
        filtered_headers = [
            h for h in headers if h.lower() not in ["cookie", "referer"] and h
        ]
        header_count = min(len(filtered_headers), 99)

        # Cookie presence ('c' or 'n') - from FoxIO ja4h.py
        cookie_str = "c" if cookies else "n"

        # Referer presence ('r' or 'n') - from FoxIO ja4h.py
        referer_str = "r" if referer else "n"

        # Language - from FoxIO ja4h.py http_language()
        if accept_language:
            lang = (
                accept_language.replace("-", "").replace(";", ",").lower().split(",")[0]
            )
            lang = lang[:4]
            lang = f"{lang}{'0' * (4 - len(lang))}"
        else:
            lang = "0000"

        # Sort headers and create hash
        sorted_headers = sorted([h.lower() for h in filtered_headers])
        header_hash = sha_encode(sorted_headers) if sorted_headers else "000000000000"

        # Sort cookies and create hash - from FoxIO ja4h.py
        if cookies:
            sorted_cookies = sorted([c.lower() for c in cookies])
            cookie_hash = sha_encode(sorted_cookies)
            # Cookie values hash (not used here, set to empty)
            cookie_values_hash = "000000000000"
        else:
            cookie_hash = "000000000000"
            cookie_values_hash = "000000000000"

        # Format matches FoxIO: {method}{version}{cookie}{referer}{header_count}{lang}_{header_hash}_{cookie_hash}_{cookie_values}
        return f"{method_str}{ver_str}{cookie_str}{referer_str}{header_count:02d}{lang}_{header_hash}_{cookie_hash}_{cookie_values_hash}"


# Convenience functions for common use cases


def fingerprint_tcp_connection(transport: Any) -> str | None:
    """
    Generate JA4TCP fingerprint from a Twisted transport.

    Args:
        transport: Twisted transport object

    Returns:
        JA4TCP fingerprint or None
    """
    try:
        fp = JA4TCPFingerprint(transport)
        return fp.generate()
    except Exception as e:
        log.msg(f"Error generating JA4TCP fingerprint: {e}")
        return None


def fingerprint_ssh_kex(
    kex_algorithms: list[str],
    encryption_algorithms: list[str],
    mac_algorithms: list[str],
    compression_algorithms: list[str],
) -> str:
    """
    Generate JA4SSH fingerprint from SSH key exchange parameters.

    Args:
        kex_algorithms: Key exchange algorithms
        encryption_algorithms: Encryption algorithms
        mac_algorithms: MAC algorithms
        compression_algorithms: Compression algorithms

    Returns:
        JA4SSH fingerprint
    """
    return JA4SSHFingerprint.generate(
        kex_algorithms, encryption_algorithms, mac_algorithms, compression_algorithms
    )
