#!/usr/bin/env python3
"""Attack: capture a valid message and replay it later.

Even without breaking the encryption, an attacker who records a legitimate
(authenticated) message could resend it to repeat its effect -- e.g. re-run a
"delete file" command. SiFT puts a strictly increasing sequence number in every
authenticated header, so a replayed message carries a stale number and is
rejected before it is acted on.
"""

from _harness import banner, blocked, keyed_pair, leaked, note
from siftprotocols.siftmtp import SiFT_MTP_Error


def run() -> bool:
    banner("Message replay")
    client, server = keyed_pair()

    client.send_msg(client.type_command_req, b"del important.txt")
    captured = client.peer_socket.sent
    note("attacker records a valid 'del important.txt' message off the wire")

    server.peer_socket.inbox = captured
    typ, pt = server.receive_msg()
    note(f"server accepts it once (legitimate delivery): {pt!r}")

    server.peer_socket.inbox = captured  # replay the identical bytes
    note("attacker replays the identical bytes...")
    try:
        server.receive_msg()
        leaked("replayed message was accepted a second time!")
        return False
    except SiFT_MTP_Error as e:
        blocked(f"rejected: {e.err_msg}")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
