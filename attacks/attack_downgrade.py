#!/usr/bin/env python3
"""Attack: rewrite the header to force an older/weaker protocol version, or
otherwise mangle the (unencrypted) header.

The 16-byte header travels in the clear, so an attacker can try to edit it -- for
example to advertise the insecure SiFT v0.5. But the header is bound into the
AES-GCM authentication tag as associated data, so any header edit that survives
the explicit version/type checks still fails tag verification. Version downgrade
is refused outright; every other header bit-flip fails closed.
"""

from _harness import banner, blocked, keyed_pair, leaked, note
from siftprotocols.siftmtp import SiFT_MTP_Error


def run() -> bool:
    banner("Protocol downgrade / header tampering")
    ok = True
    client, server = keyed_pair()

    client.send_msg(client.type_command_req, b"pwd")
    base = client.peer_socket.sent

    # 1) Downgrade the version field (bytes 0..1) to v0.5.
    wire = bytearray(base)
    wire[0:2] = b"\x00\x05"
    server.peer_socket.inbox = bytes(wire)
    note("attacker rewrites version 01 00 -> 00 05 (SiFT v0.5)")
    try:
        server.receive_msg()
        leaked("downgraded version accepted!")
        ok = False
    except SiFT_MTP_Error as e:
        blocked(f"rejected: {e.err_msg}")

    # 2) Flip a header byte that passes the static checks (e.g. the reserved field).
    server2 = keyed_pair()[1]
    server2._recv_key = server._recv_key  # same key space as our sender
    # Rebuild a fresh valid message from a matching sender to keep sequence sane.
    client2, server2 = keyed_pair()
    client2.send_msg(client2.type_command_req, b"pwd")
    wire2 = bytearray(client2.peer_socket.sent)
    wire2[15] ^= 0x01  # reserved byte -- authenticated as AAD
    server2.peer_socket.inbox = bytes(wire2)
    note("attacker flips a reserved header byte (authenticated as AAD)")
    try:
        server2.receive_msg()
        leaked("header modification accepted!")
        ok = False
    except SiFT_MTP_Error as e:
        blocked(f"rejected: {e.err_msg}")

    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
