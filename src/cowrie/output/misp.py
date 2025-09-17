from __future__ import annotations
import os
from pathlib import Path
from typing import Any

from pymisp import MISPAttribute, MISPEvent, MISPSighting, MISPObject

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

try:
    from pymisp import ExpandedPyMISP as PyMISP
except ImportError:
    from pymisp import PyMISP as PyMISP


class Output(cowrie.core.output.Output):
    """
    MISP Upload Plugin for Cowrie.

    This Plugin creates events for:
    1. File uploads/downloads
    2. SSH/Telnet login attempts (brute force)
    3. Command execution

    Events are now consolidated to create one comprehensive event per session
    """

    def start(self) -> None:
        """
        Start output plugin
        """
        misp_url = CowrieConfig.get("output_misp", "base_url")
        misp_key = CowrieConfig.get("output_misp", "api_key")
        misp_verifycert = CowrieConfig.getboolean("output_misp", "verify_cert")
        self.debug = CowrieConfig.getboolean("output_misp", "debug", fallback=False)
        self.publish = CowrieConfig.getboolean(
            "output_misp", "publish_event", fallback=False
        )

        self.misp_api = PyMISP(
            url=misp_url, key=misp_key, ssl=misp_verifycert, debug=False
        )

        # Session tracking for comprehensive session events
        self.session_tracking: dict[str, dict[str, Any]] = {}

        # Configure what events to handle
        self.handle_sessions = CowrieConfig.getboolean(
            "output_misp", "handle_session_events", fallback=True
        )

    def stop(self) -> None:
        """
        Stop output plugin - create final events for any remaining sessions
        """
        # Create events for any active sessions that didn't properly close
        for session_id, session_data in self.session_tracking.items():
            if not session_data.get("event_created", False):
                has_activity = (
                    session_data.get("auth_success", False)
                    or session_data.get("commands", [])
                    or session_data.get("downloads", [])
                    or session_data.get("uploads", [])
                )

                if has_activity and self.handle_sessions:
                    self.create_session_event(session_id, session_data)

    def write(self, event: dict[str, Any]) -> None:
        """
        Process events and submit to MISP
        """
        # First, track all session events for proper aggregation
        if "session" in event and "src_ip" in event:
            session_id = event["session"]
            src_ip = event["src_ip"]
            timestamp = event.get("timestamp", "unknown")

            # Initialize session tracking if needed
            if session_id not in self.session_tracking:
                self.session_tracking[session_id] = {
                    "src_ip": src_ip,
                    "dst_ip": event.get("dst_ip", "unknown"),
                    "dst_port": event.get("dst_port", "unknown"),
                    "protocol": event.get("protocol", "unknown"),
                    "start_time": timestamp,
                    "commands": [],
                    "dangerous_commands": [],
                    "downloads": [],
                    "uploads": [],
                    "usernames": set(),
                    "passwords": set(),
                    "login_attempts": [],
                    "auth_success": False,
                    "client_details": {},
                    "event_created": False,
                    "end_time": None,
                    "duration": None,
                }

                # Track client details for SSH sessions
                if "protocol" in event and event["protocol"] == "ssh":
                    # Add SSH-specific details
                    if "version" in event:
                        self.session_tracking[session_id]["client_details"][
                            "version"
                        ] = event["version"]
                    if "hassh" in event:
                        self.session_tracking[session_id]["client_details"]["hassh"] = (
                            event["hassh"]
                        )

            # Update last activity time
            self.session_tracking[session_id]["last_time"] = timestamp

            if event["eventid"] == "cowrie.session.file_download":
                # Track file downloads in session data
                download_info = {
                    "url": event.get("url", "unknown"),
                    "outfile": event.get("outfile", "unknown"),
                    "shasum": event.get("shasum", "unknown"),
                    "timestamp": timestamp,
                }
                self.session_tracking[session_id]["downloads"].append(download_info)

                # Option 1: Create immediate malware events as in the old script
                # This gives instant malware upload without waiting for session to end
                file_sha_attrib = self.find_attribute(
                    "malware-sample", f"*|{event['shasum']}"
                )
                if file_sha_attrib:
                    if self.debug:
                        log.msg("MISP: File known, add sighting")
                    self.add_sighting(event, file_sha_attrib)
                # Don't create immediate event - let the session event handle it

            elif event["eventid"] == "cowrie.session.file_upload":
                # Track file uploads in session data
                upload_info = {
                    "outfile": event.get("outfile", "unknown"),
                    "shasum": event.get("shasum", "unknown"),
                    "timestamp": timestamp,
                }
                self.session_tracking[session_id]["uploads"].append(upload_info)

                # Handle file sighting/event creation with existing logic
                file_sha_attrib = self.find_attribute("sha256", event["shasum"])
                if file_sha_attrib:
                    if self.debug:
                        log.msg("MISP: File known, add sighting")
                    self.add_sighting(event, file_sha_attrib)

            # Handle login attempts (both failed and successful)
            elif event["eventid"] in ["cowrie.login.failed", "cowrie.login.success"]:
                success = event["eventid"] == "cowrie.login.success"

                # Update session login details
                self.session_tracking[session_id]["usernames"].add(event["username"])
                if "password" in event:
                    self.session_tracking[session_id]["passwords"].add(
                        event["password"]
                    )

                # Track login attempt details
                attempt_details = {
                    "username": event["username"],
                    "successful": success,
                    "timestamp": timestamp,
                }
                if "password" in event:
                    attempt_details["password"] = event["password"]
                elif "fingerprint" in event:
                    attempt_details["fingerprint"] = event["fingerprint"]

                self.session_tracking[session_id]["login_attempts"].append(
                    attempt_details
                )

                # Mark login success
                if success:
                    self.session_tracking[session_id]["auth_success"] = True

            # Handle command execution
            elif event["eventid"] == "cowrie.command.input":
                command = event["input"]

                # Store command in session data
                cmd_details = {"command": command, "timestamp": timestamp}
                self.session_tracking[session_id]["commands"].append(cmd_details)

                # Flag dangerous commands
                dangerous_commands = [
                    "wget",
                    "curl",
                    "nc",
                    "netcat",
                    "ncat",
                    "chmod +x",
                    "rm -rf",
                    "dd if=/dev/",
                    "> /dev/sd",
                ]

                if any(dc in command for dc in dangerous_commands):
                    self.session_tracking[session_id]["dangerous_commands"].append(
                        cmd_details
                    )
                    if self.debug:
                        log.msg(f"MISP: Dangerous command detected: {command}")

            # When a session closes, create a comprehensive event
            elif event["eventid"] == "cowrie.session.closed":
                # Set end time and calculate duration
                self.session_tracking[session_id]["end_time"] = timestamp

                if "duration" in event:
                    self.session_tracking[session_id]["duration"] = event["duration"]

                # Only create events for sessions with meaningful activity
                if not self.session_tracking[session_id].get("event_created", False):
                    has_activity = (
                        self.session_tracking[session_id].get("auth_success", False)
                        or self.session_tracking[session_id].get("commands", [])
                        or self.session_tracking[session_id].get("downloads", [])
                        or self.session_tracking[session_id].get("uploads", [])
                    )

                    # Create a comprehensive session event if there's activity worth reporting
                    if has_activity and self.handle_sessions:
                        self.create_session_event(
                            session_id, self.session_tracking[session_id]
                        )
                        self.session_tracking[session_id]["event_created"] = True

    def find_attribute(self, attribute_type, searchterm):
        """
        Returns a matching attribute or None if nothing was found.
        """
        result = self.misp_api.search(
            controller="attributes", type_attribute=attribute_type, value=searchterm
        )

        if result["Attribute"]:
            return result["Attribute"][0]
        return None

    def add_standard_tags(self, misp_event):
        """
        Add standard tags to all events
        """
        misp_event.add_tag("tlp:white")
        misp_event.add_tag("type:honeypot")
        misp_event.add_tag('honeypot-basic:data-capture="attacks"')
        misp_event.add_tag('honeypot-basic:containment="block"')
        misp_event.add_tag("type:OSINT")
        return misp_event

    def add_sighting(self, event, attribute):
        """
        Add a sighting to an existing attribute
        """
        sighting = MISPSighting()
        sighting.source = "{} (Cowrie)".format(event["sensor"])

        try:
            self.misp_api.add_sighting(sighting, attribute)
            if self.debug:
                log.msg(f"MISP: Added sighting to attribute {attribute['id']}")
        except Exception as e:
            log.msg(f"MISP: Error adding sighting: {e}")

    def create_session_event(self, session_id, session_data):
        """
        Creates a comprehensive MISP event for an entire session using custom objects
        """
        misp_event = MISPEvent()

        # Create appropriate title based on activity
        if session_data.get("auth_success", False):
            title_prefix = "Successful Login"
        else:
            title_prefix = "Attempted Access"

        if session_data.get("commands"):
            num_commands = len(session_data.get("commands", []))
            title_prefix += f" with {num_commands} Commands"

        if session_data.get("downloads"):
            title_prefix += f" and {len(session_data.get('downloads', []))} Downloads"

        if session_data.get("uploads"):
            title_prefix += f" and {len(session_data.get('uploads', []))} Uploads"

        protocol = session_data.get("protocol", "unknown").upper()
        misp_event.info = f"{protocol} {title_prefix} from {session_data.get('src_ip', 'unknown')} (Cowrie Session {session_id[:8]})"

        # Add standard tags
        self.add_standard_tags(misp_event)
        misp_event.add_tag("cowrie:session")

        # Add session metadata
        ip_attr = MISPAttribute()
        ip_attr.type = "ip-src"
        ip_attr.value = session_data.get("src_ip", "unknown")
        ip_attr.to_ids = True
        misp_event.add_attribute(**ip_attr)

        # Add session details - create a custom object with standalone=True to bypass templates
        session_object = MISPObject(name="cowrie-session", standalone=True)

        # Add session attributes with correct syntax
        session_object.add_attribute(
            type="text", value=session_id, object_relation="id"
        )

        if session_data.get("start_time"):
            session_object.add_attribute(
                type="datetime",
                value=session_data["start_time"],
                object_relation="start-time",
            )

        if session_data.get("end_time"):
            session_object.add_attribute(
                type="datetime",
                value=session_data["end_time"],
                object_relation="end-time",
            )

        if session_data.get("duration"):
            session_object.add_attribute(
                type="text",
                value=str(session_data["duration"]),
                object_relation="duration",
            )

        if session_data.get("dst_ip"):
            session_object.add_attribute(
                type="ip-dst", value=session_data["dst_ip"], object_relation="dst-ip"
            )

        if session_data.get("dst_port"):
            session_object.add_attribute(
                type="port",
                value=str(session_data["dst_port"]),
                object_relation="dst-port",
            )

        # Add client details if available
        if session_data.get("client_details"):
            for key, value in session_data["client_details"].items():
                session_object.add_attribute(
                    type="text", value=str(value), object_relation=f"client-{key}"
                )

        misp_event.add_object(session_object)

        # Add login attempts as a custom object
        if session_data.get("login_attempts"):
            auth_object = MISPObject(name="cowrie-authentication", standalone=True)

            # Add usernames
            for username in session_data.get("usernames", []):
                auth_object.add_attribute(
                    type="text", value=username, object_relation="username"
                )

            # Add success status
            auth_object.add_attribute(
                type="text",
                value=str(session_data.get("auth_success", False)).lower(),
                object_relation="authentication-success",
            )

            # Add detailed login attempts
            for i, attempt in enumerate(session_data.get("login_attempts", [])):
                attempt_details = (
                    f"User: {attempt.get('username', 'unknown')}, "
                    + (
                        f"Password: {attempt.get('password', 'unknown')}, "
                        if "password" in attempt
                        else ""
                    )
                    + (
                        f"Fingerprint: {attempt.get('fingerprint', 'unknown')}, "
                        if "fingerprint" in attempt
                        else ""
                    )
                    + f"Success: {attempt.get('successful', False)}"
                )
                auth_object.add_attribute(
                    type="text",
                    value=attempt_details,
                    object_relation=f"attempt-{i + 1}",
                )

            misp_event.add_object(auth_object)

            # Add MITRE ATT&CK tagging for authentication
            if session_data.get("auth_success", False):
                misp_event.add_tag(
                    'misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078"'
                )
            else:
                misp_event.add_tag(
                    'misp-galaxy:mitre-attack-pattern="Brute Force - T1110"'
                )

        # Add commands as a custom object (no template constraints)
        if session_data.get("commands"):
            command_object = MISPObject(name="cowrie-commands", standalone=True)

            # Add a summary attribute
            command_object.add_attribute(
                type="text",
                value=f"{len(session_data['commands'])} commands executed",
                object_relation="summary",
            )

            # Add each command
            for i, cmd in enumerate(session_data["commands"]):
                command_value = cmd.get("command", "")
                # Skip empty commands
                if command_value.strip():
                    command_object.add_attribute(
                        type="text",
                        value=command_value,
                        object_relation=f"command-{i + 1}",
                    )

                    # Add timestamp if available
                    if "timestamp" in cmd and cmd["timestamp"] != "unknown":
                        command_object.add_attribute(
                            type="datetime",
                            value=cmd["timestamp"],
                            object_relation=f"timestamp-{i + 1}",
                        )

            # Only add the object if it has attributes
            if command_object.attributes:
                misp_event.add_object(command_object)
                # Add MITRE ATT&CK tagging
                misp_event.add_tag(
                    'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'
                )

        if session_data.get("downloads"):
            for download in session_data["downloads"]:
                # Add the actual malware sample as a separate attribute to the event (not part of an object)
                if "outfile" in download and download["shasum"] != "unknown":
                    malware_attr = MISPAttribute()
                    malware_attr.type = "malware-sample"
                    malware_attr.value = (
                        os.path.basename(download["outfile"]) + "|" + download["shasum"]
                    )
                    malware_attr.data = Path(
                        download["outfile"]
                    )  # This uploads the actual binary
                    malware_attr.expand = "binary"
                    malware_attr.comment = (
                        f"File downloaded to Cowrie honeypot in session {session_id}"
                    )
                    malware_attr.to_ids = True
                    misp_event.add_attribute(**malware_attr)

                # Still create the file object for structured data
                file_object = MISPObject(name="cowrie-file-download", standalone=True)

                if "url" in download and download["url"] != "unknown":
                    file_object.add_attribute(
                        type="url", value=download["url"], object_relation="url"
                    )

                if "outfile" in download and download["outfile"] != "unknown":
                    file_object.add_attribute(
                        type="filename",
                        value=os.path.basename(download["outfile"]),
                        object_relation="filename",
                    )

                if "timestamp" in download and download["timestamp"] != "unknown":
                    file_object.add_attribute(
                        type="datetime",
                        value=download["timestamp"],
                        object_relation="timestamp",
                    )

                # Only add the object if it has attributes
                if file_object.attributes:
                    misp_event.add_object(file_object)

            # Add MITRE ATT&CK tagging for file downloads
            misp_event.add_tag(
                'misp-galaxy:mitre-attack-pattern="Ingress Tool Transfer - T1105"'
            )

        # Add uploads as custom file objects
        if session_data.get("uploads"):
            for upload in session_data["uploads"]:
                file_object = MISPObject(name="cowrie-file-upload", standalone=True)

                if "shasum" in upload and upload["shasum"] != "unknown":
                    file_object.add_attribute(
                        type="sha256", value=upload["shasum"], object_relation="sha256"
                    )

                if "outfile" in upload and upload["outfile"] != "unknown":
                    file_object.add_attribute(
                        type="filename",
                        value=os.path.basename(upload["outfile"]),
                        object_relation="filename",
                    )

                if "timestamp" in upload and upload["timestamp"] != "unknown":
                    file_object.add_attribute(
                        type="datetime",
                        value=upload["timestamp"],
                        object_relation="timestamp",
                    )

                file_object.add_attribute(
                    type="text",
                    value="Uploaded to honeypot",
                    object_relation="attachment-type",
                )

                # Only add the object if it has attributes
                if file_object.attributes:
                    misp_event.add_object(file_object)

            # Add MITRE ATT&CK tagging for file uploads
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Data Staged - T1074"')

        # Add comprehensive text summary
        summary_lines = [
            f"Cowrie Honeypot Session Summary for {session_id}",
            f"Protocol: {session_data.get('protocol', 'unknown').upper()}",
            f"Source IP: {session_data.get('src_ip', 'unknown')}",
            f"Start Time: {session_data.get('start_time', 'unknown')}",
            f"End Time: {session_data.get('end_time', 'unknown')}",
            f"Duration: {session_data.get('duration', 'unknown')} seconds",
            f"Authentication Success: {session_data.get('auth_success', False)}",
            f"Usernames Attempted: {', '.join(session_data.get('usernames', ['none']))}",
            f"Number of Commands: {len(session_data.get('commands', []))}",
            f"Number of Downloads: {len(session_data.get('downloads', []))}",
            f"Number of Uploads: {len(session_data.get('uploads', []))}",
        ]

        # Add command details
        if session_data.get("commands"):
            summary_lines.append("\nCommands executed:")
            for i, cmd in enumerate(session_data["commands"]):
                if cmd.get("command", "").strip():  # Skip empty commands
                    summary_lines.append(f"{i + 1}. {cmd.get('command', 'unknown')}")

        if session_data.get("downloads"):
            summary_lines.append("\nFiles downloaded:")
            for i, download in enumerate(session_data["downloads"]):
                summary_lines.append(
                    f"{i + 1}. URL: {download.get('url', 'unknown')}, "
                    + f"Filename: {os.path.basename(download.get('outfile', 'unknown'))}"
                )

        # Add upload details
        if session_data.get("uploads"):
            summary_lines.append("\nFiles uploaded:")
            for i, upload in enumerate(session_data["uploads"]):
                summary_lines.append(
                    f"{i + 1}. Filename: {os.path.basename(upload.get('outfile', 'unknown'))}, "
                    + f"SHA256: {upload.get('shasum', 'unknown')}"
                )

        summary_attr = MISPAttribute()
        summary_attr.type = "text"
        summary_attr.value = "\n".join(summary_lines)
        misp_event.add_attribute(**summary_attr)

        # Publish the event if configured
        if self.publish:
            misp_event.publish()

        result = self.misp_api.add_event(misp_event)

        if self.debug:
            log.msg(f"MISP: Session event creation result for {session_id}: {result}")

        return result
