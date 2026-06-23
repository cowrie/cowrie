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
            # OCSF "SSH Activity" (class_uid 4007) in the "Network Activity"
            # category (category_uid 4). activity_id 1 = "Open" (new session).
            ocsf["category_uid"] = 4
            ocsf["category_name"] = "Network Activity"
            ocsf["class_uid"] = 4007
            ocsf["class_name"] = "SSH Activity"
            ocsf["activity_id"] = 1
            ocsf["activity_name"] = "Open"
            # type_uid = class_uid * 100 + activity_id -> 400701
            ocsf["type_uid"] = ocsf["class_uid"] * 100 + ocsf["activity_id"]

            # The attacker side of the connection.
            ocsf["src_endpoint"] = {
                "ip": logentry["src_ip"],
                "port": logentry["src_port"],
            }
            # The honeypot side; sensor name is the listening host.
            ocsf["dst_endpoint"] = {
                "hostname": logentry["sensor"],
                "ip": logentry["dst_ip"],
                "port": logentry["dst_port"],
            }
            ocsf["connection_info"] = {
                # 1 = Inbound (attacker -> honeypot).
                "direction_id": 1,
                "protocol_name": logentry.get("protocol"),
                # Cowrie session id doubles as the connection uid.
                "uid": logentry.get("session"),
            }
            # Surface the source IP as a searchable observable. type_id 2 = IP.
            ocsf["observables"] = [
                {
                    "name": "src_endpoint.ip",
                    "type_id": 2,
                    "value": logentry["src_ip"],
                }
            ]

    return ocsf
