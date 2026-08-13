.. SPDX-FileCopyrightText: 2021-2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Output Event Code Reference
###########################

This reference documents the event ids Cowrie sends to the output plugins,
such as the JSON logging module, and the attributes each event carries.
Events are listed alphabetically. How events travel from the emitting code
to the output plugins is described in :doc:`EVENT_PIPELINE`.

Shared Attributes
*****************

Every event carries these attributes, added automatically:

* `eventid`: the event id, e.g. ``cowrie.session.connect``
* `message`: human readable message
* `sensor`: name of the sensor, by default the hostname
* `timestamp`: timestamp in ISO8601 format in UTC time zone
* `session`: unique session identifier
* `src_ip`: attacker IP address

Events emitted from a connection also carry `protocol` (``ssh`` or
``telnet``), `src_port`, `dst_ip` and `dst_port`. The `session`, `src_ip`
and `protocol` values always describe the connection itself; an event
cannot overwrite them with attacker-supplied data such as a forwarding
request's claimed originator.

An event dispatched after its connection closed (for example a download
that finished after the attacker disconnected) carries `late: true`.

The ``cowrie.abuseipdb.*`` events are operational rather than
session-scoped: they carry no `session` and appear only as lines in
``cowrie.log``, not in the output plugins.

Reference
*********

cowrie.abuseipdb.ratelimited
============================

AbuseIPDB asked Cowrie to slow down; reporting is paused.

Attributes:

    * `retry_after`: seconds to wait before reporting again
    * `wake_at`: when reporting resumes (absent on immediate retries)

cowrie.abuseipdb.reportedip
===========================

An attacker IP was reported to AbuseIPDB.

Attributes:

    * `IP`: the reported IP address
    * `confidence`: AbuseIPDB's abuse confidence score for the IP

cowrie.abuseipdb.reportfail
===========================

Reporting an IP to AbuseIPDB failed.

Attributes:

    * `IP`: the IP address that could not be reported
    * `response`: HTTP status code (on HTTP errors)
    * `reason`: HTTP status message (on HTTP errors)
    * `exception`: the raised exception (on network errors)

cowrie.abuseipdb.started
========================

The AbuseIPDB output plugin started.

Attributes: none beyond the shared attributes.

cowrie.abuseipdb.wakeup
=======================

The AbuseIPDB plugin resumed reporting after a rate-limit pause.

Attributes: none beyond the shared attributes.

cowrie.client.fingerprint
=========================

The attacker attempted to log in with an SSH public key.

Attributes:

    * `username`: username
    * `fingerprint`: the key fingerprint
    * `key`: the key in OpenSSH format
    * `type`: type of key, typically ssh-rsa or ssh-dsa

cowrie.client.kex
=================

The client's SSH key exchange proposal and the derived
`HASSH <https://github.com/salesforce/hassh>`_ client fingerprint.

Attributes:

    * `hassh`: HASSH fingerprint of the client
    * `hasshAlgorithms`: the algorithm string the fingerprint is built from
    * `kexAlgs`: key exchange algorithms offered by the client
    * `keyAlgs`: host key algorithms offered by the client
    * `encCS`: encryption algorithms offered by the client
    * `macCS`: MAC algorithms offered by the client
    * `compCS`: compression algorithms offered by the client
    * `langCS`: languages offered by the client

cowrie.client.malformed_packet
==============================

An SSH packet could not be parsed; the connection is dropped.

Attributes:

    * `messagenum`: SSH message number of the offending packet
    * `datalen`: length of the packet payload
    * `data`: first 256 bytes of the payload, hex encoded

cowrie.client.size
==================

Width and height of the attacker's terminal as communicated through the
SSH protocol.

Attributes:

    * `width`: terminal width in characters
    * `height`: terminal height in characters

cowrie.client.var
=================

The client set an environment variable, via the SSH ``env`` request or
Telnet NEW-ENVIRON.

Attributes:

    * `name`: variable name
    * `value`: variable value

cowrie.client.version
=====================

The remote SSH client's identification string.

Attributes:

    * `version`: the client version string

cowrie.command.chpasswd
=======================

The attacker attempted to change a password with ``chpasswd``.

Attributes:

    * `realm`: always ``chpasswd``
    * `username`: account the attacker tried to change

cowrie.command.failed
=====================

The attacker ran a command the emulated shell does not implement.

Attributes:

    * `input`: the command line

cowrie.command.input
====================

A command line entered by the attacker, in the shell or as input to an
interactive command.

Attributes:

    * `input`: the command line, or the line fed to a command's stdin
    * `realm`: for stdin input, the command that consumed the line
      (absent for shell command lines)

cowrie.command.success
======================

Legacy event marking accepted command input; still emitted by ``busybox``
applet lookups and the ``passwd`` and ``php`` stdin handlers.

Attributes:

    * `input`: the accepted input
    * `realm`: the consuming command (absent for busybox)

cowrie.direct-tcpip.data
========================

Data the attacker attempted to send through a refused direct-tcpip
forwarding request.

Attributes:

    * `dst_ip`: requested destination address
    * `dst_port`: requested destination port
    * `data`: the payload
    * `id`: SSH channel id (when emitted from the shell backend)

cowrie.direct-tcpip.ja4
=======================

A `JA4 <https://github.com/FoxIO-LLC/ja4>`_ TLS client fingerprint
computed from a TLS ClientHello sent through a port forward.

Attributes:

    * `ja4`: the JA4 fingerprint
    * `dst_ip`: destination address
    * `dst_port`: destination port

cowrie.direct-tcpip.ja4h
========================

A JA4H HTTP client fingerprint computed from an HTTP request sent through
a port forward.

Attributes:

    * `ja4h`: the JA4H fingerprint
    * `dst_ip`: destination address
    * `dst_port`: destination port

cowrie.direct-tcpip.redirect
============================

A direct-tcpip request was rewritten to a different destination, as
configured with ``ssh.forward_redirect``.

Attributes:

    * `new_ip`: address the connection was redirected to
    * `new_port`: port the connection was redirected to
    * `dst_ip`: destination the attacker requested
    * `dst_port`: port the attacker requested
    * `orig_ip`: originator address claimed by the client
    * `orig_port`: originator port claimed by the client

cowrie.direct-tcpip.request
===========================

The client asked to open a direct-tcpip channel — an attempt to proxy
traffic through the honeypot.

Attributes:

    * `dst_ip`: requested destination address
    * `dst_port`: requested destination port
    * `orig_ip`: originator address claimed by the client
    * `orig_port`: originator port claimed by the client

cowrie.direct-tcpip.tunnel
==========================

A direct-tcpip request was tunneled through a real upstream proxy, as
configured with ``ssh.forward_tunnel``.

Attributes:

    * `new_ip`: upstream proxy address
    * `new_port`: upstream proxy port
    * `dst_ip`: destination the attacker requested
    * `dst_port`: port the attacker requested
    * `orig_ip`: originator address claimed by the client
    * `orig_port`: originator port claimed by the client

cowrie.greynoise.result
=======================

GreyNoise's reputation verdict for the attacker IP: a known Internet-wide
scanner, or a known benign service. The verdict is in the `message` text.

Attributes: none beyond the shared attributes.

cowrie.log.closed
=================

A TTY session recording was finalized.

Attributes:

    * `ttylog`: filename of the session log, replayable with ``playlog``
    * `size`: size in bytes
    * `duration_ms`: duration of the recording in milliseconds
    * `shasum`: SHA-256 checksum of the attacker input only (honeypot
      generated output is not included)
    * `duplicate`: whether this attacker input has been seen before

cowrie.log.open
===============

A TTY log file was opened for a session channel.

Attributes:

    * `ttylog`: filename of the session log

cowrie.login.failed
===================

Failed authentication.

Attributes:

    * `username`: username
    * `password`: password (password and keyboard-interactive attempts)
    * `fingerprint`, `key`, `type`: the offered key (public-key attempts)

cowrie.login.success
====================

Successful authentication.

Attributes:

    * `username`: username
    * `password`: password (password and keyboard-interactive attempts)
    * `fingerprint`, `key`, `type`: the offered key (public-key attempts)

cowrie.proxy.backend_connect_error
==================================

Proxy mode: the backend could not be reached; the attacker connection is
dropped.

Attributes:

    * `backend_ip`: backend address
    * `backend_port`: backend port
    * `error`: the connection error

cowrie.proxy.backend_connected
==============================

Proxy mode: the connection to the backend was established.

Attributes:

    * `backend_ip`: backend address
    * `backend_port`: backend port
    * `local_ip`: local address of the proxy's client socket
    * `local_port`: local port of the proxy's client socket

cowrie.proxy.backend_disconnected
=================================

Proxy mode: the connection to the backend was torn down.

Attributes:

    * `backend_ip`: backend address
    * `backend_port`: backend port
    * `local_ip`: local address of the proxy's client socket
    * `local_port`: local port of the proxy's client socket

cowrie.proxy.client_disconnect
==============================

Proxy mode: the proxy lost its connection to the backend VM or host.

Attributes:

    * `vm_id`: pool VM identifier (pool backend)
    * `honey_ip`, `honey_port`: backend address and port (static backend)

cowrie.proxy.ssh
================

Proxy mode: per-packet trace of SSH messages passing through the proxy.
High volume; only emitted when enabled in the configuration.

Attributes:

    * `direction`: whether the packet went to the backend or the attacker
    * `packet`: SSH message name
    * `payload`: packet payload

cowrie.reversedns.connect
=========================

The PTR record resolved for the attacker's IP address.

Attributes:

    * `ptr`: the PTR record
    * `ttl`: DNS time-to-live

cowrie.reversedns.forward
=========================

The PTR record resolved for the destination of a forwarding request.

Attributes:

    * `dst_ip`: the forwarding destination that was resolved
    * `ptr`: the PTR record
    * `ttl`: DNS time-to-live

cowrie.session.closed
=====================

Session closed.

Attributes:

    * `duration_ms`: duration of the session in milliseconds

cowrie.session.connect
======================

New connection; the first event of every session.

Attributes:

    * `src_ip`: attacker address
    * `src_port`: attacker port
    * `dst_ip`: honeypot address
    * `dst_port`: honeypot port

cowrie.session.file_download
============================

A file entered the honeypot: fetched with ``wget``, ``curl``, ``tftp`` or
``ftpget``, or attacker-supplied content captured from stdin or a shell
redirect.

Attributes:

    * `url`: source URL (absent for stdin and redirect captures)
    * `outfile`: where the file is stored, named after its checksum
    * `shasum`: SHA-256 checksum of the file
    * `destfile`: path the attacker wrote to (where applicable)
    * `duplicate`: whether this file has been seen before

cowrie.session.file_download.failed
===================================

A download the attacker attempted did not complete.

Attributes:

    * `url`: the URL that failed
    * `error`: the failure reason (where available)

cowrie.session.file_upload
==========================

File uploaded to Cowrie through SFTP or SCP.

Attributes:

    * `filename`: name of the uploaded file
    * `outfile`: where the file is stored, named after its checksum
    * `shasum`: SHA-256 checksum of the file
    * `destfile`: path the attacker wrote to (SCP)
    * `duplicate`: whether this file has been seen before (SCP)

cowrie.session.input
====================

A line the attacker typed into an interactive command's stdin.

Attributes:

    * `realm`: the command that consumed the line
    * `input`: the line

cowrie.session.params
=====================

The emulated system parameters chosen for this session. This event
carries no message text; it appears only in structured output.

Attributes:

    * `arch`: emulated architecture

cowrie.telnet.error
===================

The Telnet negotiation parser could not handle the client's byte stream;
the connection is dropped.

Attributes:

    * `error`: the parse error

cowrie.telnet.exploit_attempt
=============================

A Telnet NEW-ENVIRON ``USER`` value matching the GNU inetutils telnetd
authentication bypass (CVE-2026-24061) was seen.

Attributes:

    * `cve`: the CVE identifier
    * `name`: environment variable name
    * `value`: environment variable value

cowrie.telnet.exploit_success
=============================

The emulated CVE-2026-24061 bypass succeeded and the attacker was logged
in (requires ``telnet.cve_2026_24061_vulnerable``).

Attributes:

    * `cve`: the CVE identifier
    * `username`: user the attacker was logged in as
    * `original_username`: username before the injection
    * `attempted_command`: command injected via the ``-f`` payload

cowrie.telnet.option
====================

A Telnet option negotiation step from the client, useful for client
fingerprinting.

Attributes:

    * `command`: ``WILL``, ``WONT``, ``DO`` or ``DONT``
    * `option_name`: name of the negotiated option
    * `option_byte`: option code

cowrie.tunnelproxy-tcpip.data
=============================

Data the attacker sent through an established CONNECT tunnel, recorded
before being relayed upstream.

Attributes:

    * `data`: the payload

cowrie.urlhaus.submitted
========================

The URLhaus output plugin finished submitting a malware download URL.

Attributes:

    * `url`: the submitted URL
    * `result`: ``success`` or ``error``
    * `http_status`: HTTP status code (on HTTP errors)

cowrie.virustotal.scanfile
==========================

The VirusTotal scan result for a file that entered the honeypot.

Attributes:

    * `sha256`: SHA-256 checksum of the file
    * `is_new`: whether the file was new to VirusTotal
    * `positives`: number of engines flagging the file (known files)
    * `total`: number of engines consulted (known files)
    * `scan_date`: when the file was last scanned (known files)
    * `scans`: per-engine scan results (known files)

cowrie.virustotal.scanurl
=========================

The VirusTotal scan result for a URL the attacker fetched from.

Attributes:

    * `url`: the scanned URL
    * `is_new`: whether the URL was new to VirusTotal
    * `positives`: number of engines flagging the URL (known URLs)
    * `total`: number of engines consulted (known URLs)
    * `scan_date`: when the URL was last scanned (known URLs)
    * `scans`: per-engine scan results (known URLs)
