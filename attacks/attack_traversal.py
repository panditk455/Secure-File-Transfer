#!/usr/bin/env python3
"""Attack: a *legitimately authenticated* user tries to escape their directory.

The interesting adversary here is an insider: someone with valid credentials who
tries to read or write outside their own root using ``..``, absolute paths, or
odd characters. SiFT stops this two independent ways -- a strict filename
allowlist and a realpath-containment check -- and records each attempt as a
security event that raises a path_traversal alert.
"""

from _harness import banner, blocked, LoopbackServer, note


def run() -> bool:
    banner("Path traversal by an authenticated user")
    srv = LoopbackServer()
    cmdp, _ = srv.login_client()
    ok = True

    attempts = [
        ("mkd", "../escape"),
        ("chd", ".."),
        ("del", "../../etc/passwd"),
        ("dnl", "..%2f..%2fsecret"),
        ("upl", "/etc/hosts"),
    ]
    for command, name in attempts:
        req = {"command": command, "param_1": name}
        if command == "upl":
            req.update({"param_2": 10, "param_3": b"\x00" * 32})
        res = cmdp.send_command(req)
        outcome = res["result_1"]
        if outcome in ("failure", "reject"):
            blocked(f"{command} {name!r} -> {outcome}: {res.get('result_2', '')}")
        else:
            print(f"  [VULNERABLE] {command} {name!r} -> {outcome}")
            ok = False

    import time
    time.sleep(0.2)
    traversal_events = [e for e in srv.monitor.events() if e["event"] == "traversal_attempt"]
    alerts = [a for a in srv.monitor.alerts() if a["rule"] == "path_traversal"]
    note(f"monitor recorded {len(traversal_events)} traversal_attempt events and "
         f"{len(alerts)} path_traversal alert(s)")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
