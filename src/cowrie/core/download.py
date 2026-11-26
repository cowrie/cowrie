# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Shared machinery for the commands that fetch files from the network.
# ABOUTME: Rate limiting, address-pinned HTTP connections and artifact capture.

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urljoin, urlparse

import treq
from twisted.internet.defer import Deferred, inlineCallbacks, succeed
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.internet.protocol import Protocol, connectionDone
from twisted.python.failure import Failure
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS, ResponseDone
from twisted.web.http import PotentialDataLoss

from cowrie.core.config import CowrieConfig
from cowrie.core.network import outbound_bind_address, resolve_allowed
from cowrie.core.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from twisted.internet.interfaces import IPushProducer, IReactorCore
    from twisted.web.client import URI
    from twisted.web.iweb import IResponse

    from cowrie.core.artifact import Artifact

# Redirect codes that send the client to a new location.
_REDIRECT_CODES = (301, 302, 303, 307, 308)


class BlockedAddress(Exception):
    """The requested host resolves to an address the honeypot must not reach."""

    def __init__(self, host: str) -> None:
        super().__init__(f"blocked address for host {host}")
        self.host = host


class UnreachableAddress(Exception):
    """The requested host has no route the honeypot can take."""

    def __init__(self, host: str) -> None:
        super().__init__(f"no route to host {host}")
        self.host = host


class TooManyRedirects(Exception):
    """A redirect chain ran past its hop limit."""


def outbound_rate_limiter(command: str) -> RateLimiter:
    """Build the outbound rate limiter for one fetching command.

    Each command reads its own ``[shell] <command>_rate_limit_*`` settings so
    an operator can loosen one without loosening the rest.
    """
    return RateLimiter(
        enabled=CowrieConfig.getboolean(
            "shell", f"{command}_rate_limit_enabled", fallback=True
        ),
        max_requests=CowrieConfig.getint(
            "shell", f"{command}_rate_limit_requests", fallback=5
        ),
        window_seconds=CowrieConfig.getint(
            "shell", f"{command}_rate_limit_window", fallback=60
        ),
        max_keys=CowrieConfig.getint(
            "shell", f"{command}_rate_limit_max_hosts", fallback=1000
        ),
    )


class _PinnedEndpointFactory:
    """Builds connections to one pre-validated address.

    The URI's hostname still drives TLS verification and SNI; only the
    address we connect to is fixed.
    """

    def __init__(self, reactor: IReactorCore, address: str, policy: Any = None) -> None:
        self._reactor = reactor
        self._address = address
        self._policy = policy if policy is not None else BrowserLikePolicyForHTTPS()

    def endpointForURI(self, uri: URI) -> Any:
        endpoint = HostnameEndpoint(
            self._reactor,
            self._address,
            uri.port,
            bindAddress=(outbound_bind_address(), 0),
        )
        if uri.scheme == b"https":
            return wrapClientTLS(
                self._policy.creatorForNetloc(uri.host, uri.port), endpoint
            )
        return endpoint


def pinned_agent(reactor: IReactorCore, address: str, policy: Any = None) -> Agent:
    """An HTTP agent that connects to ``address`` instead of resolving again.

    The blocklist check resolves the hostname once; connecting by name would
    resolve it a second time, letting a malicious DNS server answer the
    validation lookup with a public address and the connection lookup with a
    private one.
    """
    agent = Agent.usingEndpointFactory(
        reactor, _PinnedEndpointFactory(reactor, address, policy)
    )
    return cast("Agent", agent)


@inlineCallbacks
def fetch(
    reactor: IReactorCore,
    url: str,
    method: str = "get",
    headers: dict[Any, Any] | None = None,
    timeout: int = 10,
    max_redirects: int = 5,
) -> Generator[Deferred, Any, Any]:
    """Fetch ``url``, validating every hop and connecting to what was validated.

    Redirects are followed here rather than by the agent so each new location
    is checked against the blocklist; an agent following them itself would
    reach whatever the redirect names. With ``max_redirects`` at 0 the
    redirect response is returned as-is, for callers that report redirects
    instead of following them.
    """
    for hop in range(max_redirects + 1):
        host = urlparse(url).hostname or ""
        address = yield resolve_allowed(host)
        if address is None:
            raise BlockedAddress(host)
        if ipaddress.ip_address(address).version == 6:
            # Fetching over IPv6 is out of reach twice over: the outbound
            # source address is an IPv4 one, and treq cannot even render a URL
            # whose host is an IPv6 literal (hyperlink IDNA-encodes the host,
            # which rejects the colons). Report what a host without an IPv6
            # route reports.
            raise UnreachableAddress(host)

        response = yield getattr(treq, method)(
            url=url,
            agent=pinned_agent(reactor, address),
            allow_redirects=False,
            headers=headers,
            timeout=timeout,
        )

        location = response.headers.getRawHeaders("location")
        if not max_redirects or response.code not in _REDIRECT_CODES or not location:
            return response
        if hop == max_redirects:
            raise TooManyRedirects

        url = urljoin(url, location[0])


class _BodyReader(Protocol):
    """Hands each chunk of a response body to a collector, and fires
    ``finished`` once, when the body ends, fails, or is stopped."""

    def __init__(self, collector: Callable[[bytes], None]) -> None:
        self.collector = collector
        self.finished: Deferred[None] | None = None

    def dataReceived(self, data: bytes) -> None:
        if self.finished is None:
            return
        try:
            self.collector(data)
        except BaseException:
            finished, self.finished = self.finished, None
            self.stop()
            finished.errback(Failure())

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        finished, self.finished = self.finished, None
        if finished is None:
            return
        if reason.check(ResponseDone, PotentialDataLoss):
            finished.callback(None)
        else:
            finished.errback(reason)

    def stop(self) -> None:
        """Close the connection; nothing more reaches the collector."""
        self.finished = None
        if self.transport is not None:
            # A response body's transport is a producer; stopping it closes
            # the connection.
            cast("IPushProducer", self.transport).stopProducing()


def collect_body(
    response: IResponse, collector: Callable[[bytes], None]
) -> Deferred[None]:
    """Pass each chunk of ``response``'s body to ``collector``, like
    treq.collect, but cancelling the result closes the connection, so a
    stalled or unwanted transfer stops instead of running on. A collector
    that raises also closes it, and the result fails with that error."""
    if response.length == 0:
        return succeed(None)
    reader = _BodyReader(collector)
    finished: Deferred[None] = Deferred(lambda _: reader.stop())
    reader.finished = finished
    response.deliverBody(reader)
    return finished


def capture_download(
    command: Any,
    artifact: Artifact,
    url: str,
    outfile: str | None = None,
    size: int = 0,
) -> None:
    """Record a completed download: honeyfs entry plus the session event.

    ``outfile`` is the path inside the honeyfs the attacker asked for, or
    None when the payload was written to stdout and never landed in the
    fake filesystem.
    """
    if outfile and command.protocol.user:
        command.fs.mkfile(
            outfile,
            command.user["uid"],
            command.user["gid"],
            size,
            33188,
        )
        command.fs.update_realfile(command.fs.getfile(outfile), artifact.shasumFilename)

    command.protocol.events.dispatch(
        "cowrie.session.file_download",
        "Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
        url=url,
        outfile=artifact.shasumFilename,
        shasum=artifact.shasum,
        duplicate=artifact.duplicate,
    )


def report_download_failure(command: Any, url: str) -> None:
    """Record a download that never completed, discarding its temp file."""
    artifact = getattr(command, "artifact", None)
    if artifact is not None:
        artifact.close()

    command.protocol.events.dispatch(
        "cowrie.session.file_download.failed",
        "Attempt to download file(s) from URL (%(url)s) failed",
        url=url,
    )
