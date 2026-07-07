#!/usr/bin/env python3
"""Attack: flip a bit in an encrypted message in transit.

An active man-in-the-middle can modify ciphertext on the wire. Against a scheme
that only encrypts (no authentication), a flipped ciphertext bit silently flips
the corresponding plaintext bit. SiFT uses AES-256-GCM, so any modification is
caught by the authentication tag and the message is rejected -- fail closed.
"""

from _harness import banner, blocked, keyed_pair, leaked, note
from siftprotocols import monitoring
from siftprotocols.siftmtp import SiFT_MTP_Error


def run() -> bool:
    banner("Ciphertext tampering (bit-flip in transit)")
    mon = monitoring.SecurityMonitor()
    client, server = keyed_pair()
    server.monitor = mon

    # Control: an untouched message decrypts fine.
    client.send_msg(client.type_command_req, b"transfer 100 to alice")
    server.peer_socket.inbox = client.peer_socket.sent
    typ, pt = server.receive_msg()
    note(f"untouched message decrypts OK -> {pt!r}")

    # Attack: capture the next message and flip a ciphertext byte.
    client.peer_socket.sent = b""
    client.send_msg(client.type_command_req, b"transfer 100 to alice")
    wire = bytearray(client.peer_socket.sent)
    wire[20] ^= 0x40  # byte 20 is inside the ciphertext (header is 0..15)
    server.peer_socket.inbox = bytes(wire)
    note("attacker flips one ciphertext byte...")

    try:
        server.receive_msg()
        leaked("tampered message was accepted!")
        return False
    except SiFT_MTP_Error as e:
        blocked(f"rejected: {e.err_msg}")

    if any(e["event"] == monitoring.EVT_MAC_FAILURE for e in mon.events()):
        note("monitor recorded a mac_failure security event (feeds tamper detection)")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
