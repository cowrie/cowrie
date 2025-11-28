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
