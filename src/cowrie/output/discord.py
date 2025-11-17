"""
Modern Discord webhook output plugin with queued sending.

Responsibilities:
- Queue events and send Discord webhook POST requests sequentially.
- Respect rate limits (HTTP 429) and retry transient server/network errors.
- Format each event as a single Discord embed with clipped fields.
"""

import json
from collections import deque
from io import BytesIO
import zlib as _zlib
from typing import Any, cast, TYPE_CHECKING
from twisted.internet import reactor, defer
from twisted.internet.defer import Deferred
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer, readBody

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from twisted.web.iweb import IBodyProducer

# -----------------
# Constants (Discord limits and plugin defaults)
# -----------------
EMBED_TITLE_MAX = 256
EMBED_DESC_MAX = 4096
EMBED_FIELD_VALUE_MAX = 1024
EMBED_MAX_FIELDS = 25
DEFAULT_DELAY = 0.3          # delay between successful sends
RETRY_DELAY = 2.0            # delay before retrying transient failures
MAX_RETRIES = 5              # max retry attempts for non-429 errors


class Output(cowrie.core.output.Output):
    """Discord webhook output plugin with sequential queue and retry logic."""

    _SKIP_KEYS = frozenset({"eventid", "message", "timestamp"})
    _LOG_PREFIX = "log_"

    # Lifecycle
    def start(self):
        self.url = CowrieConfig.get("output_discord", "url").encode("utf8")
        self.agent = client.Agent(reactor)
        # no persistent clock attribute needed; use reactor.callLater directly
        # Queue state
        self._reactor: Any = reactor  # typed loosely for callLater
        self._queue: deque[dict[str, Any]] = deque()
        self._sending: bool = False
        self._stopped: bool = False
        # Runtime tunables (allow override via config if present)
        self._default_delay: float = CowrieConfig.getfloat("output_discord", "default_delay", fallback=DEFAULT_DELAY)
        self._retry_delay: float = CowrieConfig.getfloat("output_discord", "retry_delay", fallback=RETRY_DELAY)
        self._max_retries: int = CowrieConfig.getint("output_discord", "max_retries", fallback=MAX_RETRIES)

    def stop(self):
        self._stopped = True
        self._sending = False
        self._queue.clear()

    # Public API
    def write(self, event: dict[str, Any]) -> None:
        """Queue an event and kick off sending if idle."""
        if self._stopped:
            return
        self._queue.append({"attempts": 0, **self._build_embed(event)})
        self._process_queue()

    def postentry(self, entry: dict[str, Any]) -> Deferred:
        return self._send_http(entry)

    # Queue handling
    def _process_queue(self) -> None:
        """Send next queued item if not already sending."""
        if self._stopped or self._sending or not self._queue:
            return
        self._sending = True
        entry = self._queue.popleft()
        d = self._send_http(entry)
        d.addCallback(self._after_result, entry)
        d.addErrback(self._after_error, entry)

    def _schedule(self, delay: float) -> None:
        self._reactor.callLater(delay, self._process_queue)

    # HTTP / Response handling
    def _send_http(self, entry: dict[str, Any]) -> "Deferred[tuple[int, float | None]]":
        """Issue the webhook POST request and return Deferred with (code, retry_after)."""
        headers = http_headers.Headers({b"Content-Type": [b"application/json"]})
        body_payload = {k: v for k, v in entry.items() if k != "attempts"}
        body_payload["allowed_mentions"] = {"parse": []}
        body = cast("IBodyProducer", FileBodyProducer(BytesIO(json.dumps(body_payload).encode("utf8"))) )
        d = self.agent.request(b"POST", self.url, headers, body)

        @defer.inlineCallbacks
        def _unwrap(resp: Any) -> Any:
            retry_after = None
            if resp.code == 429:
                try:
                    raw = yield readBody(resp)
                    data = json.loads(raw.decode("utf8"))
                    ra = data.get("retry_after")
                    if isinstance(ra, (int, float)) and ra >= 0:
                        retry_after = float(ra)
                except Exception:
                    retry_after = None
            defer.returnValue((resp.code, retry_after))

        return d.addCallback(_unwrap)  # type: ignore[no-any-return]

    def _after_result(self, result: tuple[int, float | None], entry: dict[str, Any]) -> None:
        status_code, retry_after = result
        attempts = entry.get("attempts", 0)
        # Decide next action
        if status_code == 429:  # rate limit
            self._queue.appendleft(entry)
            delay = retry_after if retry_after is not None else self._retry_delay
        elif status_code >= 500 and attempts < self._max_retries:  # transient server error
            entry["attempts"] = attempts + 1
            self._queue.append(entry)
            delay = self._retry_delay
        else:  # success or give up
            delay = self._default_delay
        # Mark idle before scheduling next so _process_queue can start again
        self._sending = False
        self._schedule(delay)

    def _after_error(self, failure: Any, entry: dict[str, Any]) -> None:
        attempts = entry.get("attempts", 0)
        if attempts < self._max_retries:
            entry["attempts"] = attempts + 1
            self._queue.append(entry)
            delay = self._retry_delay
        else:
            delay = self._default_delay
        self._sending = False
        self._schedule(delay)

    # Embed construction
    def _build_embed(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return payload dict with one embed representing the event."""
        eventid = str(event.get("eventid", "Cowrie Event"))
        description = self._clip(str(event.get("message", "")), EMBED_DESC_MAX)
        timestamp = str(event.get("timestamp", ""))
        embed = {
            "title": self._clip(eventid, EMBED_TITLE_MAX),
            "description": description,
            "timestamp":  timestamp,
            "color": self._color_from_eventid(eventid),
            "fields": [],
        }
        # Build fields with simple comprehension, clipped and limited.
        keys = [
            k for k in sorted(event)
            if k not in self._SKIP_KEYS and not k.startswith(self._LOG_PREFIX) and event.get(k) is not None
        ]
        if keys:
            embed["fields"] = [
                {
                    "name": self._clip(str(k), EMBED_TITLE_MAX),
                    "value": self._clip(self._stringify(event[k]), EMBED_FIELD_VALUE_MAX),
                    "inline": False,
                }
                for k in keys[:EMBED_MAX_FIELDS]
            ]
        return {"embeds": [embed]}

    # Utility
    def _clip(self, s: str, max_len: int) -> str:
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

    def _stringify(self, val: Any) -> str:
        try:
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            if isinstance(val, (dict, list, tuple, set)):
                obj = list(val) if isinstance(val, (set, tuple)) else val
                try:
                    return json.dumps(obj, ensure_ascii=False, default=str)
                except Exception:
                    return str(val)
            return str(val)
        except Exception:
            return repr(val)

    def _color_from_eventid(self, eventid: str) -> int:
        # Use CRC32 truncated to 24 bits for a deterministic color.
        return (_zlib.crc32(eventid.encode("utf8")) & 0xFFFFFF)
