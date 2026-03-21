# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


#  cowrie.client.fingerprint
#  cowrie.client.size
#  cowrie.client.var
#  cowrie.client.version
#  cowrie.command.failed
#  cowrie.command.success
#  cowrie.direct-tcpip.data
#  cowrie.direct-tcpip.request
#  cowrie.log.closed
#  cowrie.login.failed
#  cowrie.login.success
#  cowrie.session.closed
#  cowrie.session.connect
#  cowrie.session.file_download
#  cowrie.session.file_upload

from __future__ import annotations


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
        case "cowrie.file.file_download" | "cowrie.file.file_upload":
            cefExtensions["filehash"] = logentry["filehash"]
            cefExtensions["filePath"] = logentry["filename"]
            cefExtensions["fsize"] = logentry["size"]

    # 'out' 'outcome'  request, rt

    cefList = []
    for key in cefExtensions:
        value = str(cefExtensions[key])
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
