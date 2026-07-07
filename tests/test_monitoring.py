"""Tests for the security monitoring / detection layer."""

from __future__ import annotations

from siftprotocols import monitoring


def test_brute_force_alert():
    mon = monitoring.SecurityMonitor(failed_login_threshold=3, failed_login_window_s=60)
    for _ in range(3):
        mon.record(monitoring.EVT_LOGIN_FAILURE, username="mallory")
    alerts = [a for a in mon.alerts() if a["rule"] == "brute_force_login"]
    assert alerts and alerts[0]["subject"] == "mallory"


def test_tampering_alert_on_mac_failure_spike():
    mon = monitoring.SecurityMonitor(mac_failure_threshold=3, mac_failure_window_s=30)
    for _ in range(3):
        mon.record(monitoring.EVT_MAC_FAILURE, typ="command_req")
    assert any(a["rule"] == "tampering_suspected" for a in mon.alerts())


def test_traversal_alert():
    mon = monitoring.SecurityMonitor()
    mon.record(monitoring.EVT_TRAVERSAL_ATTEMPT, name="../secret")
    assert any(a["rule"] == "path_traversal" for a in mon.alerts())


def test_below_threshold_no_alert():
    mon = monitoring.SecurityMonitor(failed_login_threshold=5)
    for _ in range(4):
        mon.record(monitoring.EVT_LOGIN_FAILURE, username="alice")
    assert not mon.alerts()


def test_events_and_summary():
    mon = monitoring.SecurityMonitor()
    mon.record(monitoring.EVT_SESSION_START, peer="1.2.3.4:5")
    mon.record(monitoring.EVT_LOGIN_SUCCESS, username="alice")
    summary = mon.summary()
    assert summary[monitoring.EVT_SESSION_START] == 1
    assert summary[monitoring.EVT_LOGIN_SUCCESS] == 1
    # since_seq filtering
    first_seq = mon.events()[0]["seq"]
    assert all(e["seq"] > first_seq for e in mon.events(since_seq=first_seq))


def test_jsonl_logfile(tmp_path):
    logfile = tmp_path / "events.jsonl"
    mon = monitoring.SecurityMonitor(logfile=str(logfile))
    mon.record(monitoring.EVT_LOGIN_SUCCESS, username="alice")
    import json
    lines = logfile.read_text().strip().splitlines()
    assert json.loads(lines[0])["event"] == monitoring.EVT_LOGIN_SUCCESS
