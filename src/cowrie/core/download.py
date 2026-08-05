# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Shared machinery for the commands that fetch files from the network.
# ABOUTME: Rate limiting, address-pinned HTTP connections and artifact capture.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS

from cowrie.core.config import CowrieConfig
from cowrie.core.network import outbound_bind_address
from cowrie.core.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from twisted.internet.interfaces import IReactorCore
    from twisted.web.client import URI

    from cowrie.core.artifact import Artifact


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
    return Agent.usingEndpointFactory(
        reactor, _PinnedEndpointFactory(reactor, address, policy)
    )


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
