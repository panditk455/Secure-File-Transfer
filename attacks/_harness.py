"""Shared harness for the SiFT attack demonstrations.

These scripts play the attacker. They exercise the *real* protocol code so the
defences shown are the real defences, not a mock. Two setups are provided:

* ``keyed_pair`` -- two MTPs that already share session keys, plus a captured
  copy of exactly what goes on the wire, for tampering/replay demos.
* ``LoopbackServer`` -- a live server on a background thread, for demonstrating
  application-layer defences like path-traversal blocking.
"""

from __future__ import annotations

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Hash import SHA256  # noqa: E402
from Crypto.Protocol.KDF import PBKDF2  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402

from siftprotocols import monitoring  # noqa: E402
from siftprotocols.siftcmd import SiFT_CMD  # noqa: E402
from siftprotocols.siftlogin import LoginGuard, SiFT_LOGIN  # noqa: E402
from siftprotocols.siftmtp import SiFT_MTP  # noqa: E402

GREEN, RED, YELLOW, BOLD, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


def banner(title: str) -> None:
    print(f"\n{BOLD}=== {title} ==={RESET}")


def blocked(msg: str) -> None:
    print(f"  {GREEN}[DEFENCE HELD]{RESET} {msg}")


def leaked(msg: str) -> None:
    print(f"  {RED}[VULNERABLE]{RESET} {msg}")


def note(msg: str) -> None:
    print(f"  {YELLOW}->{RESET} {msg}")


class CaptureSocket:
    """Records everything sent; can be primed with bytes to receive."""

    def __init__(self) -> None:
        self.sent = b""
        self.inbox = b""

    def sendall(self, b: bytes) -> None:
        self.sent += b

    def recv(self, n: int) -> bytes:
        chunk, self.inbox = self.inbox[:n], self.inbox[n:]
        return chunk


def keyed_pair():
    """Client+server MTPs sharing directional keys (as if login already happened)."""
    client = SiFT_MTP(CaptureSocket(), role="client")
    server = SiFT_MTP(CaptureSocket(), role="server")
    k_c2s, k_s2c = os.urandom(32), os.urandom(32)
    client.set_session_keys(k_c2s, k_s2c)
    server.set_session_keys(k_c2s, k_s2c)
    return client, server


def _demo_users():
    salt = os.urandom(16)
    return {"alice": {
        "pwdhash": PBKDF2("aaa", salt, 32, count=1000, hmac_hash_module=SHA256),
        "icount": 1000, "salt": salt, "rootdir": "alice/",
    }}


class LoopbackServer:
    """A live SiFT server on a background thread over a socketpair."""

    def __init__(self):
        self.key = RSA.generate(2048)
        self.monitor = monitoring.SecurityMonitor()
        self.users = _demo_users()
        self.rootdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sandbox") + os.sep
        os.makedirs(os.path.join(self.rootdir, "alice"), exist_ok=True)
        self.s_sock, self.c_sock = socket.socketpair()
        self.s_sock.settimeout(5)
        self.c_sock.settimeout(5)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            mtp = SiFT_MTP(self.s_sock, role="server", server_privkey=self.key,
                           monitor=self.monitor, peer_name="attacker")
            loginp = SiFT_LOGIN(mtp, guard=LoginGuard(monitor=self.monitor))
            loginp.set_server_users(self.users)
            user, _, _ = loginp.handle_login_server()
            cmdp = SiFT_CMD(mtp)
            cmdp.set_server_rootdir(self.rootdir)
            cmdp.set_user_rootdir(self.users[user]["rootdir"])
            while True:
                cmdp.receive_command()
        except Exception:
            pass

    def login_client(self):
        mtp = SiFT_MTP(self.c_sock, role="client", server_pubkey=self.key.publickey())
        SiFT_LOGIN(mtp).handle_login_client("alice", "aaa")
        return SiFT_CMD(mtp), mtp
