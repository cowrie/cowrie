"""
Cowrie Prometheus output.

[output_prometheus]
enabled = true
port    = 9000
"""

from __future__ import annotations

import socket
import time

from prometheus_client import start_http_server, Counter, Gauge, Histogram
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

# ────────────────────────────────────────────
#  Metric objects
# ────────────────────────────────────────────
HOST_LABEL = CowrieConfig.get("honeypot", "hostname", fallback=socket.gethostname())
BUCKETS_LEN = (0, 4, 8, 12, 16, 20, 40)
BUCKETS_DUR = (1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600)

sessions_total = Counter(
    "cowrie_sessions_total", "Total SSH/Telnet sessions", ["transport", "sensor"]
)
sessions_active = Gauge(
    "cowrie_sessions_active", "Active sessions", ["transport", "sensor"]
)
session_duration = Histogram(
    "cowrie_session_duration_seconds",
    "Session duration seconds",
    ["transport"],
    buckets=BUCKETS_DUR,
)
source_ip_total = Counter(
    "cowrie_source_ip_total", "Sessions per source IP", ["ip", "asn_country"]
)

source_ip_card = Gauge(
    "cowrie_source_ip_cardinality", "Unique source IPs seen", ["interval"]
)

login_attempts = Counter(
    "cowrie_login_attempts_total", "Login attempts", ["result", "username"]
)
password_length = Histogram(
    "cowrie_password_length", "Password length histogram", buckets=BUCKETS_LEN
)

commands_total = Counter(
    "cowrie_command_total", "Commands executed", ["command", "sensor"]
)

dl_bytes_total = Counter(
    "cowrie_file_download_bytes_total", "Downloaded bytes", ["protocol", "sensor"]
)
dl_time_hist = Histogram(
    "cowrie_file_download_time_seconds",
    "File download duration",
    ["protocol"],
    buckets=BUCKETS_DUR,
)

outbound_total = Counter(
    "cowrie_connection_outbound_total",
    "Outbound direct‑tcpip connections",
    ["dst_ip", "dst_port"],
)

loop_lag_hist = Histogram("cowrie_event_loop_lag_seconds", "Twisted reactor lag (s)")
py_exceptions = Counter(
    "cowrie_python_exceptions_total", "Uncaught Python exceptions", ["exception"]
)


class Output(cowrie.core.output.Output):
    def start(self) -> None:
        port = CowrieConfig.getint("output_prometheus", "port", fallback=9000)
        self.debug = CowrieConfig.getboolean(
            "output_prometheus", "debug", fallback=False
        )
        start_http_server(port)

        if self.debug:
            log.msg(f"[Prometheus] Exporter started on port: {port}")
            log.msg(f"[Prometheus] Host label: {HOST_LABEL}")

        # Helper structures
        self._start_times: dict[str, float] = {}
        self._srcip_seen_5m: set[str] = set()
        self._srcip_seen_60m: set[str] = set()

        # Periodic callbacks for event-loop lag & unique-IP gauges
        # task.LoopingCall(self._report_loop_lag).start(5, now=False)
        # task.LoopingCall(self._flush_unique_ip_gauges, 300, "5m").start(300, now=False)
        # task.LoopingCall(self._flush_unique_ip_gauges, 3600, "1h").start(
        #     3600, now=False
        # )

    def write(self, event: dict) -> None:
        try:
            eid = event["eventid"]

            if self.debug:
                log.msg(f"[Prometheus] Event: {eid}")

            if eid == "cowrie.session.connect":
                self._on_session_connect(event)

            elif eid == "cowrie.session.closed":
                self._on_session_closed(event)

            elif eid in ("cowrie.login.success", "cowrie.login.failed"):
                self._on_login(event, success=eid.endswith("success"))

            elif eid == "cowrie.command.input":
                self._on_command(event)

            elif eid == "cowrie.session.file_download":
                self._on_download(event)

            elif eid == "cowrie.direct-tcpip.request":
                self._on_outbound(event)

            if eid == "cowrie.session.connect":
                ip = event.get("src_ip")
                if ip:
                    self._srcip_seen_5m.add(ip)
                    self._srcip_seen_60m.add(ip)

        except Exception as e:
            if self.debug:
                log.msg(f"[Prometheus] Exception: {e!s}")
            py_exceptions.labels(exception=e.__class__.__name__).inc()

    def _on_session_connect(self, ev: dict) -> None:
        transport = ev.get("protocol", "ssh")
        sensor = HOST_LABEL
        sid = ev["session"]
        sessions_total.labels(transport, sensor).inc()
        sessions_active.labels(transport, sensor).inc()
        self._start_times[sid] = ev["time"] if "time" in ev else time.time()

        ip = ev.get("src_ip", "unknown")
        asn = ev.get("src_persist_as", "UNK")
        source_ip_total.labels(ip, asn).inc()

    def _on_session_closed(self, ev: dict) -> None:
        sid = ev["session"]
        transport = ev.get("protocol", "ssh")
        sensor = HOST_LABEL

        sessions_active.labels(transport, sensor).dec()

        start_ts = self._start_times.pop(sid, None)
        if start_ts:
            session_duration.labels(transport).observe(time.time() - start_ts)

    def _on_login(self, ev: dict, *, success: bool) -> None:
        res = "success" if success else "fail"
        user = ev.get("username", "unknown")
        passwd = ev.get("password", "")
        login_attempts.labels(res, user).inc()
        if passwd:
            password_length.observe(len(str(passwd)))

    def _on_command(self, ev: dict) -> None:
        cmd = ev.get("input", "").strip().split(" ")[0][:30]  # first token
        commands_total.labels(cmd, HOST_LABEL).inc()

    def _on_download(self, ev: dict) -> None:
        proto = ev.get("shasum", "").split(":")[0] or "unknown"
        size = int(ev.get("len", 0))
        dtime = float(ev.get("duration", 0))
        dl_bytes_total.labels(proto, HOST_LABEL).inc(size)
        dl_time_hist.labels(proto).observe(dtime)

    def _on_outbound(self, ev: dict) -> None:
        dst_ip = ev.get("dst_ip", "unknown")
        dst_port = str(ev.get("dst_port", "0"))
        outbound_total.labels(dst_ip, dst_port).inc()

    # def _report_loop_lag(self) -> None:
    #     before = time.time()
    #     reactor.callLater(0, lambda: loop_lag_hist.observe(time.time() - before))
    #
    # def _flush_unique_ip_gauges(self, interval_sec: int, label: str) -> None:
    #     s = self._srcip_seen_5m if interval_sec == 300 else self._srcip_seen_60m
    #     source_ip_card.labels(label).set(len(s))
    #     s.clear()

    def stop(self):
        pass
