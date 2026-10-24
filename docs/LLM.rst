.. SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Using the LLM Backend
#####################

The LLM (Large Language Model) backend uses AI models like OpenAI's GPT to generate
realistic shell responses. Instead of static command emulation, the LLM dynamically
generates output for any command, making the honeypot more convincing and capable
of handling unexpected inputs.

This is an experimental feature that provides a high-interaction honeypot experience
without requiring a real backend system.

Enabling the LLM Backend
************************

To use the LLM backend, change the ``backend`` option to ``llm`` in the ``[honeypot]`` section::

    [honeypot]
    backend = llm

Then configure the ``[llm]`` section with your API credentials.

Configuration
*************

API Key (Required)
==================

You must provide an API key for the LLM service. For OpenAI::

    [llm]
    api_key = sk-your-api-key-here

Get your API key from https://platform.openai.com/api-keys

Model Selection
===============

Choose which model to use. Smaller models are faster and cheaper, larger models
may provide more realistic responses::

    [llm]
    model = gpt-4o-mini

Common options:

* ``gpt-4o-mini`` - Fast and cost-effective (default)
* ``gpt-4o`` - More capable, higher cost
* ``gpt-4-turbo`` - High capability

Custom API Endpoints
====================

To use a different OpenAI-compatible API (such as a local LLM server), configure
the host and path::

    [llm]
    host = https://api.openai.com
    path = /v1/chat/completions

For local LLM servers like Ollama or text-generation-webui, point to your local endpoint::

    [llm]
    host = http://localhost:11434
    path = /v1/chat/completions

OrcaRouter Cyber Inference
==========================

`OrcaRouter <https://www.orcarouter.ai>`_ is an OpenAI-compatible AI gateway with a
named provider preset in Cowrie: **OrcaRouter Cyber Inference**. It is aimed at
security teams doing authorized work: the cyber tier carries models and defenses
for security teams, and the gateway applies its own guardrails to the endpoint
rather than relying on the model alone.

* Provider page: https://www.orcarouter.ai/cyber
* Cyber model catalog: https://www.orcarouter.ai/models?tier=cyber

A red team can use the OrcaRouter endpoint for authorized, scoped security
reasoning (for example reviewing defensive detection logic or hardening a lab);
a blue team gets the same endpoint for defensive analysis, with the gateway's
controls in front of it. Cyber-tier models are for workspaces that have
completed business verification; without that access the catalog simply does
not offer them.

Configuring OrcaRouter
----------------------

Select the provider, then choose a model. The default is ``orcarouter/auto``,
which routes automatically and works with any OrcaRouter API key::

    [llm]
    provider = orcarouter
    model = orcarouter/auto

Recommended models, in order:

* ``orcarouter/auto`` — default; automatic routing, works with any key.
* ``orcacyber-ultra-1.0`` — OrcaCyber Ultra, for security code scanning and
  multi-step reasoning over large codebases (verified security workspaces).
* ``orcacyber-zero-1.5`` — OrcaCyber Zero, driven by the OrcaCyber harness
  (verified security workspaces).
* ``orcarouter/fusion`` — general fallback model.

The model list is not hand-written: ``cowrie-orcarouter-models`` reads
OrcaRouter's live catalog for the current capability and prints the ids you can
put in ``[llm] model``::

    cowrie-orcarouter-models                       # text chat models
    cowrie-orcarouter-models --modality image      # chat models that accept images
    cowrie-orcarouter-models --capability embedding
    cowrie-orcarouter-models --json

If the catalog cannot be reached the command says so and shows a small verified
fallback list (marked degraded) instead of pretending it is live.

Authentication
--------------

Two independent choices are available; both end up as the same kind of
OrcaRouter API key, and both are stored in the credential file
(``[llm] credentials_file``, default ``var/lib/cowrie/orcarouter.json``, mode 0600).

**Use an existing API key.** Create a key in the OrcaRouter console, then::

    cowrie-orcarouter-auth --api-key

The key is read without echoing and never written to a log.

**Sign in with OAuth 2.0 + PKCE.** On the host running Cowrie::

    cowrie-orcarouter-auth

Cowrie prints an authorization URL (and tries to open a browser). Approve the
request, then paste the code shown on the consent screen. Cowrie exchanges it
for a durable API key bound to your account. Because Cowrie usually runs
headless — over SSH, in a container, or on a server whose address changes — this
uses the out-of-band code flow rather than a loopback callback. The verifier is
generated fresh for each attempt from a cryptographic RNG, only its S256
challenge is sent, and it never leaves the process.

Use ``cowrie-orcarouter-auth --status`` to see the stored credential (masked)
and ``cowrie-orcarouter-auth --clear`` to remove it. The key is the user's own:
it is billed to their account and can be revoked at
https://www.orcarouter.ai/console/authorized-apps. Revoking it does not refresh
anything — Cowrie marks the rejected credential as needing reauthentication and
the next ``cowrie-orcarouter-auth`` replaces it.

Environment overrides
---------------------

``ORCA_BASE_URL`` sets one shared self-hosted base for both origins;
``ORCA_AUTH_BASE_URL`` and ``ORCA_API_BASE_URL`` override them individually and
take precedence. Authentication uses ``https://www.orcarouter.ai`` and
inference uses ``https://api.orcarouter.ai/v1``. Remote origins must be HTTPS;
plain HTTP is accepted only for loopback. ``COWRIE_LLM_API_KEY`` still works and
takes precedence over the credential file.

Response Parameters
===================

Control how the LLM generates responses::

    [llm]
    # Maximum tokens in the response (default: 500)
    max_tokens = 500

    # Temperature: 0.0-2.0, higher = more random (default: 0.7)
    temperature = 0.7

Debugging
=========

Enable debug logging to see LLM requests and responses::

    [llm]
    debug = true

This logs the full request/response JSON to the Cowrie log file.

How It Works
************

When an attacker connects and enters a command:

1. The command is sent to the LLM along with a system prompt that instructs it to
   simulate a Linux server
2. The LLM generates realistic command output
3. The response is displayed to the attacker
4. Command history is maintained to provide context for follow-up commands

The LLM maintains conversation history (last 10 commands) to provide consistent
responses across a session. For example, if the attacker runs ``cd /tmp`` followed
by ``pwd``, the LLM will correctly respond with ``/tmp``.

Advantages
**********

* **No static signatures**: Every response is dynamically generated
* **Handles any command**: Unlike the shell backend, unknown commands get realistic responses
* **Consistent sessions**: Maintains context across commands
* **Easy setup**: No virtual filesystem or backend VMs required

Limitations
***********

* **API costs**: Each command requires an API call
* **Latency**: Responses take 1-3 seconds depending on the model
* **State consistency**: The LLM may occasionally be inconsistent with filesystem state
* **No real execution**: Downloads and file operations are simulated, not real

Security Considerations
***********************

* Your API key is sent with every request - keep your configuration file secure
* LLM responses are logged - review logs for any unexpected content
* The LLM cannot execute real commands - all responses are text-only

Example Configuration
*********************

Minimal configuration::

    [honeypot]
    backend = llm

    [llm]
    api_key = sk-your-api-key-here

Full configuration with all options::

    [honeypot]
    backend = llm

    [llm]
    api_key = sk-your-api-key-here
    model = gpt-4o-mini
    host = https://api.openai.com
    path = /v1/chat/completions
    max_tokens = 500
    temperature = 0.7
    debug = false
