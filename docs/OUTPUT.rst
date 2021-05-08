Output Event Code Reference
###########################

This guide documents the event id's used by Cowrie that are sent to the output modules, such as the JSON logging module.

Reference
*********

Shared Attributes
=================

These attributes are shared by all messages.

Attributes:

    * `message`: human readable message
    * `sensor`: name of the sensor, by default the hostname
    * `timestamp`: timestamp in ISO8601 format
    * `src_ip`: attacker IP address
    * `session`: unique session identifier

cowrie.client.fingerprint
=========================

Attributes:

    * username
    * fingerprint
    * key
    * type

cowrie.login.success
====================

Successful authentication.

Attributes:

    * username
    * password

cowrie.login.failed
===================

Failed authentication.

Attributes:

    * username
    * password

cowrie.client.size
===================

Width and height of the users terminal as communicated through the SSH protocol.

Attributes:

    * width
    * height

cowrie.session.file_upload
==========================

File uploaded to Cowrie, generaly through SFTP or SCP or another way.

Attributes:

    * filename
    * outfile
    * shasum

cowrie.command.input
====================

Command line input

Attributes:

    * input


cowrie.virustotal.scanfile
==========================

File sent to VT for scanning

Attributes:

    * sha256
    * is_new
    * positives
    * total

cowrie.session.connect
==========================

New connection

Attributes:

    * src_ip
    * src_port
    * dst_ip
    * dst_port

cowrie.client.version
=====================

SSH identification string

Attributes:

    * version


cowrie.client.kex
=====================

SSH Key Exchange Attributes

Attributes:

    * hassh
    * hasshAlgorithms
    * kexAlgs
    * keyAlgs

cowrie.session.closed
=====================

Session closed

Attributes:

    * duration

cowrie.log.closed
=====================

TTY Log closed

Attributes:

    * duration
    * ttylog
    * size
    * shasum
    * duplicate

cowrie.direct-tcpip.request
===========================

Request for proxying via the honeypot

Attributes:

    * dst_ip
    * dst_port
    * src_ip
    * src_port

cowrie.direct-tcpip.data
===========================

Data attempted to be sent through direct-tcpip forwarding

Attributes:

    * dst_ip
    * dst_port

cowrie.client.var
=================

Attributes:

    * name
    * value
