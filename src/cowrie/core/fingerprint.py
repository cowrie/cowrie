# ABOUTME: JA4 and JA4H fingerprinting for TLS and HTTP traffic
# ABOUTME: Parses TLS Client Hello and HTTP requests to generate fingerprints

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
developed by FoxIO:

- JA4: TLS client fingerprinting from Client Hello messages
- JA4H: HTTP client fingerprinting from request headers

These fingerprints help identify and track network clients based on their
protocol implementations and behavior patterns.
"""

from __future__ import annotations

import struct

from twisted.python import log

from cowrie.vendor.ja4.common import sha_encode, GREASE_TABLE, TLS_MAPPER


# Convert FoxIO's string-based GREASE table to integer set for our use
GREASE_VALUES = {int(k, 16) for k in GREASE_TABLE}

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

    except Exception as e:
        log.msg(f"Error parsing TLS Client Hello: {e}")
        return None
    else:
        return {
            "tls_version": tls_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "has_sni": has_sni,
            "alpn": alpn,
            "signature_algorithms": signature_algorithms,
        }


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

            header_name, header_value = line.split(":", 1)
            header_name = header_name.strip()
            header_value = header_value.strip()

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

    except Exception as e:
        log.msg(f"Error parsing HTTP request: {e}")
        return None
    else:
        return {
            "method": method,
            "version": version,
            "headers": headers,
            "cookies": cookies,
            "referer": referer,
            "accept_language": accept_language,
        }


def generate_ja4(
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


def generate_ja4h(
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
    # Method (first 2 chars, lowercase)
    method_str = method.lower()[:2]

    # Version
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

    # Cookie presence ('c' or 'n')
    cookie_str = "c" if cookies else "n"

    # Referer presence ('r' or 'n')
    referer_str = "r" if referer else "n"

    # Language
    if accept_language:
        lang = accept_language.replace("-", "").replace(";", ",").lower().split(",")[0]
        lang = lang[:4]
        lang = f"{lang}{'0' * (4 - len(lang))}"
    else:
        lang = "0000"

    # Sort headers and create hash
    sorted_headers = sorted([h.lower() for h in filtered_headers])
    header_hash = sha_encode(sorted_headers) if sorted_headers else "000000000000"

    # Sort cookies and create hash
    if cookies:
        sorted_cookies = sorted([c.lower() for c in cookies])
        cookie_hash = sha_encode(sorted_cookies)
        cookie_values_hash = "000000000000"
    else:
        cookie_hash = "000000000000"
        cookie_values_hash = "000000000000"

    # Format: {method}{version}{cookie}{referer}{header_count}{lang}_{header_hash}_{cookie_hash}_{cookie_values}
    return f"{method_str}{ver_str}{cookie_str}{referer_str}{header_count:02d}{lang}_{header_hash}_{cookie_hash}_{cookie_values_hash}"
