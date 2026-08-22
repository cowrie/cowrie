# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


# ABOUTME: Formats Cowrie events as CEF (Common Event Format) strings for
# ABOUTME: the localsyslog and textlog output plugins.
# The event ids and their attributes are documented in docs/OUTPUT.rst.

from __future__ import annotations


def escapeCefValue(value: str) -> str:
    """
    Escape a CEF extension value.

    Pairs in the extension are delimited by a space and a key is separated
    from its value by "=", so a literal "=" in a value would read as the start
    of the next pair. CEF escapes it as "\\=", the backslash itself as "\\\\",
    and a newline as "\\n" / "\\r" so one event stays on one line.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def formatCef(logentry: dict[str, str]) -> str:
    """
    Take logentry and turn into CEF string
    """
    # Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|
    # Device Version|Signature ID|Name|Severity|[Extension]
    cefVendor = "Cowrie"
    cefProduct = "Cowrie"
    cefVersion = "1.0"
    cefSignature = logentry["eventid"]
    cefName = logentry["eventid"]
    cefSeverity = "5"

    cefExtensions = {
        "app": "SSHv2",
        "destinationServicename": "sshd",
        "deviceExternalId": logentry["sensor"],
        "msg": logentry["message"],
        "src": logentry["src_ip"],
        "proto": "tcp",
    }

    match logentry["eventid"]:
        case "cowrie.session.connect":
            cefExtensions["spt"] = logentry["src_port"]
            cefExtensions["dpt"] = logentry["dst_port"]
            cefExtensions["src"] = logentry["src_ip"]
            cefExtensions["dst"] = logentry["dst_ip"]
        case "cowrie.login.success":
            cefExtensions["duser"] = logentry["username"]
            cefExtensions["outcome"] = "success"
        case "cowrie.login.failed":
            cefExtensions["duser"] = logentry["username"]
            cefExtensions["outcome"] = "failed"
        case "cowrie.session.file_download" | "cowrie.session.file_upload":
            cefExtensions["filehash"] = logentry["shasum"]
            cefExtensions["filePath"] = logentry["outfile"]
        case _:
            pass

    # 'out' 'outcome'  request, rt

    cefList = []
    for key in cefExtensions:
        value = escapeCefValue(str(cefExtensions[key]))
        cefList.append(f"{key}={value}")

    cefExtension = " ".join(cefList)

    cefString = (
        "CEF:0|"
        + cefVendor
        + "|"
        + cefProduct
        + "|"
        + cefVersion
        + "|"
        + cefSignature
        + "|"
        + cefName
        + "|"
        + cefSeverity
        + "|"
        + cefExtension
    )

    return cefString
