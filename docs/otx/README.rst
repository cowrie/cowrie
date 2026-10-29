.. SPDX-FileCopyrightText: 2026 Jari Huttunen <jari.tapani.huttunen@gmail.com>
..
.. SPDX-License-Identifier: BSD-3-Clause

AlienVault OTX Integration
##########################

The ``otx`` output plugin submits captured malware to `AlienVault OTX
<https://otx.alienvault.com/>`_ (LevelBlue Open Threat Exchange) and reports
the associated indicators in OTX pulses.

Features
********

* **File analysis**: Uploads files captured by the honeypot with the
  ``submit_file`` API for static and sandbox analysis.
* **URL analysis**: Submits malware download URLs with ``submit_url``.
* **Pulse reporting**: Adds the sample SHA-256, the download URL and the
  attacker's public IP to an OTX pulse, one pulse per UTC day.
* **Deduplication**: Each SHA-256 and URL is submitted once per Cowrie
  process, and files captured before the plugin started are skipped.
* **Restart-safe pulses**: The current pulse id is persisted in
  ``${honeypot:state_path}/otx_pulse.json`` so a restart during the same UTC
  day appends to the existing pulse.

Prerequisites
*************

You need an OTX account and API key. Sign in at
https://otx.alienvault.com/ and copy the key from your account settings (the
API page at https://otx.alienvault.com/api links to it).

Configuration
*************

Enable the plugin in ``etc/cowrie.cfg``:

.. code-block:: ini

    [output_otx]
    enabled = true
    api_key = your-otx-api-key
    upload = true
    submit_url = true
    pulse = true
    pulse_name = Cowrie honeypot samples
    public = true
    tlp = white
    tags = cowrie,honeypot
    include_url = true
    include_src_ip = true

Options
=======

``api_key``
    Your OTX API key. Required; it is sent in the ``X-OTX-API-KEY`` header.

``upload`` (default ``true``)
    Upload captured files to ``/api/v1/indicators/submit_file``.

``submit_url`` (default ``true``)
    Submit the download URL of a captured file to
    ``/api/v1/indicators/submit_url``. Only ``cowrie.session.file_download``
    events carry a URL.

``pulse`` (default ``true``)
    Report indicators in a pulse. When ``false``, files and URLs are still
    submitted for analysis but no pulse is created.

``pulse_name`` (default ``Cowrie honeypot samples``)
    Pulse name prefix. The UTC date is appended, for example ``Cowrie
    honeypot samples 2026-10-30``. The final name is kept within OTX's
    64-character limit.

``public`` (default ``true``)
    Whether pulses are visible to all OTX users. A public pulse shares the
    captured hashes, URLs and attacker IPs with the community.

``tlp`` (default ``white``)
    Traffic Light Protocol level: ``white``, ``green``, ``amber`` or ``red``.
    OTX does not allow public ``amber`` or ``red`` pulses; the plugin forces
    ``public = false`` in that case.

``tags`` (default ``cowrie,honeypot``)
    Comma-separated tags attached to every pulse.

``group_ids`` (default empty)
    Comma-separated OTX group ids the pulse is published to. You must be a
    member of the group.

``include_url`` (default ``true``)
    Add the malware download URL to the pulse as a ``URL`` indicator with the
    ``malware_hosting`` role. Only ``http`` and ``https`` URLs up to 2000
    characters are added.

``include_src_ip`` (default ``true``)
    Add the attacker's source IP to the pulse as an ``IPv4`` or ``IPv6``
    indicator with the ``scanning_host`` role. Private, loopback, link-local
    and reserved addresses are skipped.

``debug`` (default ``false``)
    Log request payloads and response details. Payloads contain no API key,
    but do contain attacker-supplied filenames and URLs.

How it works
************

On ``cowrie.session.file_download`` and ``cowrie.session.file_upload`` the
plugin locates the stored artifact (using ``outfile``, falling back to
``${honeypot:download_path}/<sha256>`` for SCP uploads) and then:

1. Uploads the file for analysis, if ``upload`` is enabled.
2. Submits the download URL for analysis, if ``submit_url`` is enabled and
   the event has a URL.
3. Creates or updates the current UTC day's pulse with the hash, URL and
   source IP, if ``pulse`` is enabled.

The first sample of a day creates the pulse with ``POST /api/v1/pulses/create``.
Later samples append indicators with ``PATCH /api/v1/pulses/<id>``. If the
pulse was deleted in the OTX web interface, the plugin notices the ``404``
and creates a new pulse for the next sample.

A file whose modification time is more than a minute old is assumed to have
been captured before the plugin started, and is not submitted again. This is
the same heuristic the VirusTotal plugin uses.

Emitted events
**************

The plugin emits ``cowrie.otx.submitted`` for every finished request, so log
output and other output plugins can record the outcome. Attributes are
documented in :doc:`../OUTPUT`. A ``success`` result describes the HTTP
request, not the malware verdict: OTX analyzes submitted files
asynchronously.

Privacy
*******

File uploads and public pulses are visible to other OTX users, including the
attacker IP addresses they contain. If your sensor sees traffic you cannot
share, set ``public = false`` and use a restrictive ``tlp``, or disable the
pulse with ``pulse = false``.

Rate limits
***********

An API key allows 10,000 requests per hour. Each captured file uses up to
three requests (file, URL, pulse create/update) and duplicates are
deduplicated locally. HTTP ``429`` responses are logged and reported as
errors; the plugin does not retry.

Troubleshooting
***************

``otx: no api_key specified in [output_otx] section``
    Set ``api_key`` or the plugin cannot authenticate. Requests will fail
    with ``403``.

``OTX file submission failed ... (HTTP 403)``
    The API key is invalid or lacks permission to submit files.

``OTX pulse creation failed ... (HTTP 400)``
    OTX rejected the pulse, typically because the configured ``tlp`` /
    ``public`` combination is invalid or a ``group_ids`` entry the account
    cannot publish to. The response body is logged.

``OTX pulse creation returned no pulse id``
    OTX accepted the pulse but returned an unexpected body. The next sample
    tries to create a new pulse.

Analysis results are not polled by this plugin. Submitted files and URLs can
be inspected on the OTX website, or through
``/api/v1/indicators/submitted_files`` and
``/api/v1/indicators/submitted_urls``.

API endpoints used
******************

* ``POST /api/v1/indicators/submit_file``
* ``POST /api/v1/indicators/submit_url``
* ``POST /api/v1/pulses/create``
* ``PATCH /api/v1/pulses/{pulse_id}``

For the full API reference, see
https://otx.alienvault.com/assets/static/external_api.html

Testing
*******

.. code-block:: console

    PYTHONPATH=src python -m unittest cowrie.test.test_otx

The integration is part of Cowrie and licensed under the same BSD license.
