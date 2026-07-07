"""Security monitoring and detection for the SiFT protocol.

This module is the "blue team" half of the project. The protocol layers
(``siftmtp``, ``siftlogin``, ``siftcmd``) emit structured security events here;
this module records them as JSON lines a SOC could ingest and runs a small set
of threshold detection rules that raise alerts (brute-force logins, a spike of
MAC-verification failures that looks like tampering, path-traversal attempts).

Nothing here is on the cryptographic hot path -- it is deliberately decoupled so
that turning monitoring off cannot weaken the protocol, only reduce visibility.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable

# Event severity levels, ordered.
INFO = "info"
WARNING = "warning"
ALERT = "alert"

# Well-known event names emitted by the protocol layers.
EVT_SESSION_START = "session_start"
EVT_SESSION_END = "session_end"
EVT_LOGIN_SUCCESS = "login_success"
EVT_LOGIN_FAILURE = "login_failure"
EVT_MAC_FAILURE = "mac_failure"
EVT_REPLAY_ATTEMPT = "replay_attempt"
EVT_SEQUENCE_VIOLATION = "sequence_violation"
EVT_TRAVERSAL_ATTEMPT = "traversal_attempt"
EVT_RATE_LIMITED = "rate_limited"
EVT_PROTOCOL_ERROR = "protocol_error"


class SecurityMonitor:
    """Collects structured security events and raises alerts on suspicious patterns.

    Thread-safe: the server handles each client on its own thread, so every
    public method takes a lock. Detection rules are intentionally simple and
    explainable -- the point is to demonstrate the monitoring/incident-response
    mindset, not to ship a production SIEM.
    """

    def __init__(
        self,
        logfile: str | None = None,
        buffer_size: int = 1000,
        failed_login_threshold: int = 5,
        failed_login_window_s: float = 60.0,
        mac_failure_threshold: int = 3,
        mac_failure_window_s: float = 30.0,
        alert_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._logfile = logfile
        self._seq = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._alerts: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._alert_sink = alert_sink

        # Detection state.
        self._failed_login_threshold = failed_login_threshold
        self._failed_login_window_s = failed_login_window_s
        self._mac_failure_threshold = mac_failure_threshold
        self._mac_failure_window_s = mac_failure_window_s
        self._failed_logins: dict[str, deque[float]] = defaultdict(deque)
        self._mac_failures: deque[float] = deque()

    # -- recording -----------------------------------------------------------

    def record(self, event: str, level: str = INFO, **fields: Any) -> dict[str, Any]:
        """Record a security event and evaluate detection rules against it."""
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "ts": round(time.time(), 3),
                "event": event,
                "level": level,
                **fields,
            }
            self._events.append(record)
            self._write(record)
            self._detect(record)
            return record

    def _write(self, record: dict[str, Any]) -> None:
        if not self._logfile:
            return
        try:
            with open(self._logfile, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            # Monitoring must never take down the protocol.
            pass

    # -- detection rules -----------------------------------------------------

    def _detect(self, record: dict[str, Any]) -> None:
        event = record["event"]
        now = record["ts"]

        if event == EVT_LOGIN_FAILURE:
            key = str(record.get("username") or record.get("peer") or "unknown")
            window = self._failed_logins[key]
            window.append(now)
            self._prune(window, now, self._failed_login_window_s)
            if len(window) >= self._failed_login_threshold:
                self._raise_alert(
                    "brute_force_login",
                    subject=key,
                    count=len(window),
                    window_s=self._failed_login_window_s,
                    detail=f"{len(window)} failed logins for '{key}' within "
                    f"{self._failed_login_window_s:.0f}s",
                )
                window.clear()

        elif event == EVT_MAC_FAILURE:
            self._mac_failures.append(now)
            self._prune(self._mac_failures, now, self._mac_failure_window_s)
            if len(self._mac_failures) >= self._mac_failure_threshold:
                self._raise_alert(
                    "tampering_suspected",
                    count=len(self._mac_failures),
                    window_s=self._mac_failure_window_s,
                    detail=f"{len(self._mac_failures)} MAC-verification failures within "
                    f"{self._mac_failure_window_s:.0f}s -- possible active tampering",
                )
                self._mac_failures.clear()

        elif event == EVT_TRAVERSAL_ATTEMPT:
            self._raise_alert(
                "path_traversal",
                subject=record.get("name"),
                detail=f"rejected path/name '{record.get('name')}'",
            )

    @staticmethod
    def _prune(window: deque[float], now: float, span: float) -> None:
        while window and now - window[0] > span:
            window.popleft()

    def _raise_alert(self, rule: str, **fields: Any) -> None:
        self._seq += 1
        alert = {
            "seq": self._seq,
            "ts": round(time.time(), 3),
            "event": "alert",
            "level": ALERT,
            "rule": rule,
            **fields,
        }
        self._alerts.append(alert)
        self._events.append(alert)
        self._write(alert)
        if self._alert_sink:
            try:
                self._alert_sink(alert)
            except Exception:
                pass

    # -- accessors (for the dashboard) --------------------------------------

    def events(self, since_seq: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if e["seq"] > since_seq]

    def alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._alerts)

    def summary(self) -> dict[str, int]:
        """Counts by event type -- a quick at-a-glance health view."""
        with self._lock:
            counts: dict[str, int] = defaultdict(int)
            for e in self._events:
                counts[e["event"]] += 1
            return dict(counts)


# A process-wide default monitor so any layer can emit without threading one
# through every constructor. Callers that want isolation (tests) create their own.
_default_monitor = SecurityMonitor()


def get_monitor() -> SecurityMonitor:
    return _default_monitor
