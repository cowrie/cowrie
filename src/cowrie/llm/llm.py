# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: LLM client for communicating with OpenAI-compatible APIs.
# ABOUTME: Sends shell commands to an LLM and returns simulated responses.

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from twisted.internet import defer, protocol, reactor
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.endpoints import HostnameEndpoint
from twisted.logger import Logger
from twisted.web.client import (
    Agent,
    HTTPConnectionPool,
    ProxyAgent,
    _HTTP11ClientFactory,  # pyright: ignore[reportPrivateUsage]
)
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer, IResponse
from zope.interface import implementer

from cowrie.core.config import CowrieConfig
from cowrie.llm import orcarouter

if TYPE_CHECKING:
    from collections.abc import Generator

    from twisted.internet.interfaces import IPushProducer
    from twisted.python import failure as tw_failure


@implementer(IBodyProducer)
class StringProducer:
    """
    Feeds a request body to the HTTP client.
    """

    def __init__(self, body: str) -> None:
        self.body = body.encode("utf-8")
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self) -> None:
        pass

    def resumeProducing(self) -> None:
        pass

    def stopProducing(self) -> None:
        pass


class SimpleResponseReceiver(protocol.Protocol):
    """
    Collects the response body from an HTTP response, up to max_size.

    A slow or misbehaving endpoint could otherwise keep streaming and grow
    this buffer without bound while holding the request open.
    """

    _log = Logger()

    def __init__(self, status_code: int, d: defer.Deferred, max_size: int) -> None:
        self.status_code = status_code
        self.buf = b""
        self.d = d
        self.max_size = max_size
        self._finished = False

    def dataReceived(self, data: bytes) -> None:
        if self._finished:
            return

        remaining = self.max_size - len(self.buf)
        if len(data) < remaining:
            self.buf += data
            return

        self.buf += data[:remaining]
        self._log.warn(
            "LLM response exceeded {max_size} bytes, truncating",
            max_size=self.max_size,
        )
        self._deliver()
        # The body transport deliverBody connects is a producer proxy for the
        # HTTP connection; stopping it closes that connection instead of
        # draining a response already past the cap.
        producer = cast("IPushProducer", self.transport)
        producer.stopProducing()

    def connectionLost(
        self, reason: tw_failure.Failure = protocol.connectionDone
    ) -> None:
        self._deliver()

    def _deliver(self) -> None:
        """Hand the body to the waiting Deferred exactly once."""
        if self._finished:
            return
        self._finished = True
        self.d.callback((self.status_code, self.buf))


class QuietHTTP11ClientFactory(_HTTP11ClientFactory):
    """
    Silences factory start/stop log messages.
    """

    noisy = False


@dataclass(frozen=True)
class ProviderPreset:
    """A named model provider with its own defaults."""

    id: str
    label: str
    host: str
    path: str
    default_model: str


# Named providers Cowrie ships a preset for. `custom` keeps the historical
# free-form host/path configuration working unchanged.
PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "openai": ProviderPreset(
        id="openai",
        label="OpenAI",
        host="https://api.openai.com",
        path="/v1/chat/completions",
        default_model="gpt-4o-mini",
    ),
    orcarouter.PROVIDER_ID: ProviderPreset(
        id=orcarouter.PROVIDER_ID,
        label=orcarouter.PROVIDER_LABEL,
        host="https://api.orcarouter.ai",
        path="/v1/chat/completions",
        default_model=orcarouter.DEFAULT_MODEL,
    ),
}
LEGACY_PROVIDER = "custom"

LEGACY_HOST = "https://api.openai.com"
LEGACY_PATH = "/v1/chat/completions"
LEGACY_MODEL = "gpt-4o-mini"


def proxy_bypassed(hostname: str) -> bool:
    """Return True when ``no_proxy`` excludes this API host.

    A proxy injected for git or another provider must not silently intercept
    OrcaRouter's auth and inference hosts. Entries match the host itself or a
    parent domain (``example.com`` or ``.example.com``); ``*`` bypasses all.
    """
    no_proxy = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    host = hostname.strip().strip("[]").lower()
    if not host:
        return False
    for raw in no_proxy.split(","):
        entry = raw.strip().lower()
        if not entry:
            continue
        if entry == "*":
            return True
        if entry.startswith("["):
            entry_host = entry[1:].split("]")[0]
        else:
            entry_host = entry.split(":")[0]
        entry_host = entry_host.lstrip(".")
        if entry_host and (host == entry_host or host.endswith("." + entry_host)):
            return True
    return False


class LLMClient:
    """
    Client for communicating with OpenAI-compatible LLM APIs.
    """

    _log = Logger()

    def __init__(self) -> None:
        self._conn_pool = HTTPConnectionPool(reactor)
        self._conn_pool._factory = QuietHTTP11ClientFactory  # pyright: ignore[reportPrivateUsage]

        configured_provider = (
            CowrieConfig.get("llm", "provider", fallback=LEGACY_PROVIDER)
            .strip()
            .lower()
        )
        self.provider = (
            configured_provider
            if configured_provider in PROVIDER_PRESETS
            else LEGACY_PROVIDER
        )
        if configured_provider and configured_provider != self.provider:
            self._log.warn(
                "Unknown [llm] provider {provider!r}; using custom host/path "
                "configuration",
                provider=configured_provider,
            )
        preset = PROVIDER_PRESETS.get(self.provider)
        self.provider_label = preset.label if preset else "custom endpoint"

        self._credential_generation = 0
        self._key_source = "none"
        self.api_key = self._resolve_api_key()

        self.model = CowrieConfig.get(
            "llm", "model", fallback=preset.default_model if preset else LEGACY_MODEL
        )
        self.host = CowrieConfig.get(
            "llm", "host", fallback=preset.host if preset else LEGACY_HOST
        ).rstrip("/")
        self.path = CowrieConfig.get(
            "llm", "path", fallback=preset.path if preset else LEGACY_PATH
        )
        self.max_tokens = CowrieConfig.getint("llm", "max_tokens", fallback=500)
        self.temperature = CowrieConfig.getfloat("llm", "temperature", fallback=0.7)
        self.debug = CowrieConfig.getboolean("llm", "debug", fallback=False)
        # Ceiling on a single API response body. Real completions are a few
        # kilobytes; the cap only stops an endpoint that keeps streaming.
        self.max_response_size = CowrieConfig.getint(
            "llm", "max_response_size", fallback=1024 * 1024
        )

        # Match the API host itself, not any URL that merely contains the
        # name (a gateway domain like anthropic.com.example is not Anthropic
        # and must not be sent Anthropic-shaped requests).
        hostname = urllib.parse.urlparse(self.host).hostname or ""

        proxy_url = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or os.environ.get("HTTP_PROXY")
        )
        self.agent: Agent | ProxyAgent
        if proxy_url and not proxy_bypassed(hostname):
            parsed = urllib.parse.urlparse(proxy_url)
            proxy_endpoint = HostnameEndpoint(
                reactor, parsed.hostname or "localhost", parsed.port or 8080
            )
            self.agent = ProxyAgent(proxy_endpoint, reactor, pool=self._conn_pool)
            self._log.info(
                "LLM using proxy: {host}:{port}", host=parsed.hostname, port=parsed.port
            )
        else:
            self.agent = Agent(reactor, pool=self._conn_pool)

        self.is_anthropic = hostname == "anthropic.com" or hostname.endswith(
            ".anthropic.com"
        )

        if not self.api_key and self._key_source != "needs_reauth":
            self._log.warn("WARNING: No LLM API key configured in [llm] section")

    def _resolve_api_key(self) -> str:
        """Resolve the credential through the provider's own seam.

        An explicit ``[llm] api_key`` (or ``COWRIE_LLM_API_KEY``) always wins.
        The OrcaRouter provider falls back to the credential file written by
        ``cowrie-orcarouter-auth``; that file is the shared result of both the
        API-key and the PKCE adapters, so nothing downstream knows which one
        produced it.
        """
        configured = CowrieConfig.get("llm", "api_key", fallback="").strip()
        if configured:
            self._key_source = "config"
            return configured
        if self.provider != orcarouter.PROVIDER_ID:
            return ""
        try:
            credential = orcarouter.CredentialStore().load()
        except orcarouter.OrcaRouterError as exc:
            self._log.error("{error}", error=str(exc))
            return ""
        if credential is None:
            return ""
        self._credential_generation = credential.generation
        if credential.needs_reauth:
            self._key_source = "needs_reauth"
            self._log.error(
                "OrcaRouter credential {key} needs reauthentication; run "
                "`cowrie-orcarouter-auth` to reconnect.",
                key=credential.masked,
            )
            return ""
        self._key_source = "credentials_file"
        return credential.key

    def _handle_auth_failure(self) -> None:
        """React to a 401 from the relay without retrying or refreshing."""
        if self.provider != orcarouter.PROVIDER_ID:
            return
        if self._key_source != "credentials_file":
            self._log.error(
                "OrcaRouter rejected the configured API key (HTTP 401); check "
                "[llm] api_key or run `cowrie-orcarouter-auth --status`."
            )
            return
        self._log.error(
            "OrcaRouter rejected the stored credential (HTTP 401); run "
            "`cowrie-orcarouter-auth` to reauthorize. The stored key is kept "
            "until a new login succeeds."
        )
        try:
            orcarouter.CredentialStore().mark_needs_reauth(self._credential_generation)
        except orcarouter.OrcaRouterError as exc:
            self._log.error("{error}", error=str(exc))

    def _build_headers(self) -> Headers:
        """Build HTTP headers with authentication."""
        if self.is_anthropic:
            return Headers(
                {
                    b"Content-Type": [b"application/json"],
                    b"x-api-key": [self.api_key.encode()],
                    b"anthropic-version": [b"2023-06-01"],
                }
            )
        return Headers(
            {
                b"Content-Type": [b"application/json"],
                b"Authorization": [f"Bearer {self.api_key}".encode()],
            }
        )

    def _format_request_body(self, prompt: list[str]) -> dict:
        """Structure the request body for the LLM API.

        Anthropic Messages API requires the system prompt as a top-level
        parameter; OpenAI uses a message with role 'system'.
        """
        system_prompt = prompt[0] if prompt else ""
        messages = []
        for message in prompt[1:]:
            if message.startswith("User:"):
                messages.append({"role": "user", "content": message[5:].strip()})
            elif message.startswith("System:"):
                messages.append({"role": "assistant", "content": message[7:].strip()})
            else:
                messages.append({"role": "user", "content": message})

        if self.is_anthropic:
            return {
                "model": self.model,
                "system": system_prompt,
                "messages": messages or [{"role": "user", "content": ""}],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
            }

        # OpenAI-compatible format
        return {
            "model": self.model,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

    def _handle_response_body(self, response: IResponse) -> Deferred[tuple[int, bytes]]:
        """Extract the response body from the HTTP response."""
        d: Deferred[tuple[int, bytes]] = defer.Deferred()
        response.deliverBody(
            SimpleResponseReceiver(response.code, d, self.max_response_size)
        )
        return d

    def _handle_connection_error(self, err: tw_failure.Failure) -> tuple[int, bytes]:
        """Handle connection errors."""
        err.trap(Exception)
        return (500, err.getErrorMessage().encode("utf-8"))

    def _send_request(self, prompt: list[str]) -> Deferred[tuple[int, bytes]]:
        """Send request to the LLM API."""
        request_body = self._format_request_body(prompt)

        if self.debug:
            self._log.info(
                "LLM request: {request}", request=json.dumps(request_body, indent=2)
            )

        url = f"{self.host}{self.path}"
        d: Deferred[Any] = self.agent.request(
            b"POST",
            url.encode("utf-8"),
            headers=self._build_headers(),
            bodyProducer=StringProducer(json.dumps(request_body)),
        )

        d.addCallbacks(self._handle_response_body, self._handle_connection_error)
        return d

    @inlineCallbacks
    def get_response(self, prompt: list[str]) -> Generator[Deferred[Any], Any, str]:
        """
        Get a response from the LLM for the given prompt.

        Args:
            prompt: List of messages. First is system prompt, rest are
                    conversation history with "User:" and "System:" prefixes.

        Returns:
            The LLM's response text, or empty string on error.
        """
        status_code, response = yield self._send_request(prompt)

        if status_code != 200:
            if status_code == 401:
                self._handle_auth_failure()
            self._log.error(
                "LLM API error (status {status}): {response}",
                status=status_code,
                response=response.decode("utf-8", errors="replace"),
            )
            return ""

        try:
            response_json = json.loads(response)
        except json.JSONDecodeError:
            self._log.failure("Failed to parse LLM response")
            return ""

        if self.debug:
            self._log.info(
                "LLM response: {response}",
                response=json.dumps(response_json, indent=2),
            )

        # OpenAI-compatible format
        if "choices" in response_json and len(response_json["choices"]) > 0:
            content: str = response_json["choices"][0]["message"]["content"]
            return content

        # Anthropic Messages API format
        if "content" in response_json and len(response_json["content"]) > 0:
            content = response_json["content"][0].get("text", "")
            return content

        self._log.error("Unexpected LLM response format: {response}", response=response)
        return ""


_shared_client: LLMClient | None = None


def get_shared_client() -> LLMClient:
    """Return the process-wide LLM client.

    Each client owns an HTTP connection pool, so building one per session
    would give a busy honeypot one pool per concurrent session against the
    same endpoint.
    """
    global _shared_client
    if _shared_client is None:
        _shared_client = LLMClient()
    return _shared_client


def reset_shared_client() -> None:
    """Drop the shared client so the next call rebuilds it (used by tests)."""
    global _shared_client
    _shared_client = None
