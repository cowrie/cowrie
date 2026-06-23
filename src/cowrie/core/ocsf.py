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

import json
import time
import uuid
from datetime import datetime
from typing import Any

# OCSF schema version this mapping targets.
OCSF_VERSION = "1.8.0"

# OCSF metadata.product describing Cowrie as the event source.
PRODUCT_NAME = "Cowrie Honeypot"
VENDOR_NAME = "Cowrie"


def _epoch_ms(timestamp: str) -> int:
    """
    Convert a Cowrie ISO-8601 UTC timestamp (e.g. '2026-06-23T14:15:26.253618Z')
    to epoch milliseconds, the integer form OCSF uses for time fields.
    """
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def _ssh_activity(
    ocsf: dict[str, Any],
    logentry: dict[str, Any],
    activity_id: int,
    activity_name: str,
) -> None:
    """
    Fill in the shared OCSF 'SSH Activity' (class_uid 4007) scaffolding.

    Endpoints are built from whatever address keys are present in the event:
    e.g. a client.version event carries no dst_ip/dst_port, so dst_endpoint
    ends up with just the hostname.
    """
    ocsf["category_uid"] = 4
    ocsf["category_name"] = "Network Activity"
    ocsf["class_uid"] = 4007
    ocsf["class_name"] = "SSH Activity"
    ocsf["activity_id"] = activity_id
    ocsf["activity_name"] = activity_name
    # type_uid = class_uid * 100 + activity_id
    ocsf["type_uid"] = ocsf["class_uid"] * 100 + activity_id

    # The attacker side; include only the fields this event actually carries.
    src_endpoint: dict[str, Any] = {}
    if "src_ip" in logentry:
        src_endpoint["ip"] = logentry["src_ip"]
    if "src_port" in logentry:
        src_endpoint["port"] = logentry["src_port"]
    if src_endpoint:
        ocsf["src_endpoint"] = src_endpoint

    # The honeypot side; sensor name is the listening host.
    dst_endpoint: dict[str, Any] = {}
    if "sensor" in logentry:
        dst_endpoint["hostname"] = logentry["sensor"]
    if "dst_ip" in logentry:
        dst_endpoint["ip"] = logentry["dst_ip"]
    if "dst_port" in logentry:
        dst_endpoint["port"] = logentry["dst_port"]
    if dst_endpoint:
        ocsf["dst_endpoint"] = dst_endpoint

    ocsf["connection_info"] = {
        # 1 = Inbound (attacker -> honeypot).
        "direction_id": 1,
        "protocol_name": logentry.get("protocol"),
        # Cowrie session id doubles as the connection uid.
        "uid": logentry.get("session"),
    }

    # Surface the source IP as a searchable observable. type_id 2 = IP.
    if "src_ip" in logentry:
        ocsf["observables"] = [
            {
                "name": "src_endpoint.ip",
                "type_id": 2,
                "value": logentry["src_ip"],
            }
        ]


def _authentication(
    ocsf: dict[str, Any],
    logentry: dict[str, Any],
    activity_id: int,
    activity_name: str,
    success: bool,
) -> None:
    """
    Fill in the OCSF 'Authentication' (class_uid 3002) scaffolding for Cowrie
    login attempts. This is the Identity & Access Management category, not
    Network Activity, so it does not share the SSH Activity scaffolding.
    """
    ocsf["category_uid"] = 3
    ocsf["category_name"] = "Identity & Access Management"
    ocsf["class_uid"] = 3002
    ocsf["class_name"] = "Authentication"
    ocsf["activity_id"] = activity_id
    ocsf["activity_name"] = activity_name
    # type_uid = class_uid * 100 + activity_id
    ocsf["type_uid"] = ocsf["class_uid"] * 100 + activity_id
    # Login attempts warrant Medium severity (3) rather than the default Info.
    ocsf["severity_id"] = 3
    # Cowrie only ever sees remote logins.
    ocsf["is_remote"] = True
    ocsf["status"] = "Success" if success else "Failure"
    ocsf["status_id"] = 1 if success else 2

    # The attacker side; include only the fields this event actually carries.
    src_endpoint: dict[str, Any] = {}
    if "src_ip" in logentry:
        src_endpoint["ip"] = logentry["src_ip"]
    if "src_port" in logentry:
        src_endpoint["port"] = logentry["src_port"]
    if src_endpoint:
        ocsf["src_endpoint"] = src_endpoint

    # The honeypot side; sensor name is the listening host.
    dst_endpoint: dict[str, Any] = {}
    if "sensor" in logentry:
        dst_endpoint["hostname"] = logentry["sensor"]
    if "dst_ip" in logentry:
        dst_endpoint["ip"] = logentry["dst_ip"]
    if "dst_port" in logentry:
        dst_endpoint["port"] = logentry["dst_port"]
    if dst_endpoint:
        ocsf["dst_endpoint"] = dst_endpoint

    # The account targeted by the login. type_id 2 = Admin, 1 = User.
    # NOTE: heuristic - privileged-looking names map to Admin, others to User.
    username = logentry["username"]
    ocsf["user"] = {
        "name": username,
        "type_id": 2 if username in ("root", "admin") else 1,
    }

    # Observables: source IP (type_id 2) and the attempted username (type_id 4).
    observables: list[dict[str, Any]] = []
    if "src_ip" in logentry:
        observables.append(
            {"name": "src_endpoint.ip", "type_id": 2, "value": logentry["src_ip"]}
        )
    observables.append({"name": "user.name", "type_id": 4, "value": username})
    ocsf["observables"] = observables

    # Password is recorded but has no dedicated OCSF home.
    ocsf["unmapped"]["password"] = logentry["password"]


def _process_activity(
    ocsf: dict[str, Any],
    logentry: dict[str, Any],
    activity_id: int,
    activity_name: str,
) -> None:
    """
    Fill in the OCSF 'Process Activity' (class_uid 1007) scaffolding for
    commands the attacker runs in the shell. This is the System Activity
    category; it carries no network endpoints (the source IP survives only in
    raw_data), just the device and the process that was launched.
    """
    ocsf["category_uid"] = 1
    ocsf["category_name"] = "System Activity"
    ocsf["class_uid"] = 1007
    ocsf["class_name"] = "Process Activity"
    ocsf["activity_id"] = activity_id
    ocsf["activity_name"] = activity_name
    # type_uid = class_uid * 100 + activity_id
    ocsf["type_uid"] = ocsf["class_uid"] * 100 + activity_id
    # Command execution warrants Low severity (2).
    ocsf["severity_id"] = 2

    # The honeypot the command ran on. type_id 1 = Server.
    ocsf["device"] = {"hostname": logentry["sensor"], "type_id": 1}

    # The launched process. cmd_line is the full input; name is the program,
    # i.e. the first whitespace-separated token (e.g. "ls" from "ls -la").
    cmd = logentry["input"]
    tokens = cmd.split()
    ocsf["process"] = {
        "cmd_line": cmd,
        "name": tokens[0] if tokens else cmd,
    }


def _filesystem_activity(
    ocsf: dict[str, Any],
    logentry: dict[str, Any],
    activity_id: int,
    activity_name: str,
) -> None:
    """
    Fill in the shared OCSF 'File System Activity' (class_uid 1001) scaffolding.
    The acting process is always Cowrie itself; the per-event file object is
    filled in by the caller.
    """
    ocsf["category_uid"] = 1
    ocsf["category_name"] = "System Activity"
    ocsf["class_uid"] = 1001
    ocsf["class_name"] = "File System Activity"
    ocsf["activity_id"] = activity_id
    ocsf["activity_name"] = activity_name
    # type_uid = class_uid * 100 + activity_id
    ocsf["type_uid"] = ocsf["class_uid"] * 100 + activity_id

    # Cowrie is the process touching the file.
    ocsf["actor"] = {"process": {"name": "cowrie", "uid": "cowrie"}}
    # The honeypot the file lives on. type_id 1 = Server.
    ocsf["device"] = {"hostname": logentry["sensor"], "type_id": 1}


def formatOCSF(logentry: dict[str, Any]) -> dict[str, Any]:
    """
    Take a Cowrie logentry and turn it into an OCSF event (a dict ready to be
    json.dumps'd by the output plugin).

    OCSF is a JSON schema, not a delimited string: each event declares its
    class/category/activity via *_uid numeric codes plus human-readable *_name
    fields, and carries strongly-typed objects like src_endpoint / dst_endpoint.
    """
    eventid = logentry["eventid"]
    now_ms = int(time.time() * 1000)

    # Fields common to every OCSF event we emit.
    ocsf: dict[str, Any] = {
        "metadata": {
            # event_uid is a unique id for *this* OCSF record (not the session).
            "event_uid": str(uuid.uuid4()),
            "labels": ["honeypot"],
            # When Cowrie observed/processed the event (now), in epoch ms.
            "logged_time": now_ms,
            "processed_time": now_ms,
            "product": {
                "name": PRODUCT_NAME,
                # Cowrie's per-sensor uuid identifies the producing instance.
                "uid": logentry.get("uuid"),
                "vendor_name": VENDOR_NAME,
            },
            "version": OCSF_VERSION,
        },
        "message": logentry.get("message"),
        # time = when the event actually happened, from the Cowrie timestamp.
        "time": _epoch_ms(logentry["timestamp"]),
        # 1 = Informational. Tune per-event below if some warrant higher.
        "severity_id": 1,
        # Preserve the untouched original event for lossless downstream use.
        "raw_data": json.dumps(logentry, sort_keys=True, separators=(",", ":")),
        # Cowrie keys that have no dedicated OCSF home go here.
        "unmapped": {
            "eventid": eventid,
            "session": logentry.get("session"),
        },
    }

    match eventid:
        case "cowrie.session.connect":
            # activity_id 1 = "Open" (a new session is established).
            _ssh_activity(ocsf, logentry, 1, "Open")
        case "cowrie.client.version":
            # activity_id 99 = "Other"; the client's SSH version banner.
            _ssh_activity(ocsf, logentry, 99, "Client Banner")
            ocsf["unmapped"]["client_version"] = logentry["version"]
        case "cowrie.client.kex":
            # activity_id 99 = "Other"; the client's key-exchange offer.
            _ssh_activity(ocsf, logentry, 99, "Key Exchange")
            # OCSF HASSH object: the algorithm string plus its MD5 fingerprint.
            # algorithm_id 1 = MD5 (hassh is an MD5 digest). The individual
            # kex/key/enc/mac/comp algorithm lists are left in raw_data only.
            ocsf["client_hassh"] = {
                "algorithm": logentry["hasshAlgorithms"],
                "fingerprint": {
                    "algorithm": "MD5",
                    "algorithm_id": 1,
                    "value": logentry["hassh"],
                },
            }
        case "cowrie.login.success":
            # activity_id 1 = "Logon".
            _authentication(ocsf, logentry, 1, "Logon", success=True)
        case "cowrie.command.input":
            # activity_id 1 = "Launch".
            _process_activity(ocsf, logentry, 1, "Launch")
        case "cowrie.log.closed":
            # activity_id 99 = "Other"; the TTY session log file being closed.
            _filesystem_activity(ocsf, logentry, 99, "Close")
            # Cowrie reports duration in seconds (as a string); OCSF wants ms.
            ocsf["duration"] = int(float(logentry["duration"]) * 1000)
            path = logentry["ttylog"]
            shasum = logentry["shasum"]
            ocsf["file"] = {
                # algorithm_id 3 = SHA-256.
                "hashes": [
                    {"algorithm": "SHA-256", "algorithm_id": 3, "value": shasum}
                ],
                # TTY logs are named after their SHA-256 digest, so the file
                # name is the basename of the path.
                "name": path.rsplit("/", 1)[-1],
                "path": path,
                "size": logentry["size"],
                # type_id 1 = Regular File.
                "type_id": 1,
            }
            # Observable is the file hash. type_id 8 = Hash.
            ocsf["observables"] = [
                {
                    "name": "file.hashes[0].value",
                    "type_id": 8,
                    "value": shasum,
                }
            ]
            ocsf["unmapped"]["duplicate"] = logentry["duplicate"]
            ocsf["unmapped"]["src_ip"] = logentry["src_ip"]

    return ocsf
