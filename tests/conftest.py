"""Shared test fixtures and helpers for the SiFT test suite.

Two harnesses are provided:

* ``FakeSocket`` -- an in-memory socket for deterministic single-message MTP tests
  (send once, tamper the bytes, feed them back to a receiver).
* ``loopback_session`` -- a real ``socket.socketpair`` with the server protocol
  running on a background thread, for full login/command/transfer round-trips.
"""

from __future__ import annotations

import os
import socket
import sys
import threading

import pytest
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siftprotocols import monitoring  # noqa: E402
from siftprotocols.siftcmd import SiFT_CMD  # noqa: E402
from siftprotocols.siftlogin import LoginGuard, SiFT_LOGIN  # noqa: E402
from siftprotocols.siftmtp import SiFT_MTP  # noqa: E402

# Low iteration count keeps the fast PBKDF2 tests fast; production uses 100k.
TEST_ICOUNT = 1000


class FakeSocket:
    """A minimal in-memory stand-in for a socket for single-message tests."""

    def __init__(self) -> None:
        self.sent = b""
        self.inbox = b""

    def sendall(self, b: bytes) -> None:
        self.sent += b

    def recv(self, n: int) -> bytes:
        chunk, self.inbox = self.inbox[:n], self.inbox[n:]
        return chunk


@pytest.fixture(scope="session")
def rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


def make_user(username: str, password: str, icount: int = TEST_ICOUNT) -> dict:
    salt = os.urandom(16)
    pwdhash = PBKDF2(password, salt, 32, count=icount, hmac_hash_module=SHA256)
    return {"pwdhash": pwdhash, "icount": icount, "salt": salt, "rootdir": username + "/"}


@pytest.fixture
def users():
    return {"alice": make_user("alice", "aaa"), "bob": make_user("bob", "bbb")}


def paired_keyed_mtps():
    """Two MTPs sharing directional keys (login already 'done'), for AEAD tests."""
    sender = SiFT_MTP(FakeSocket(), role="client")
    receiver = SiFT_MTP(FakeSocket(), role="server")
    k_c2s, k_s2c = os.urandom(32), os.urandom(32)
    sender.set_session_keys(k_c2s, k_s2c)
    receiver.set_session_keys(k_c2s, k_s2c)
    return sender, receiver


class LoopbackSession:
    """A live client<->server session over socketpair; server runs on a thread."""

    def __init__(self, rsa_keys, users, rootdir, monitor=None):
        privkey, pubkey = rsa_keys
        self.monitor = monitor or monitoring.SecurityMonitor()
        self.guard = LoginGuard(monitor=self.monitor)
        self._users = users
        self._rootdir = rootdir
        self.s_sock, self.c_sock = socket.socketpair()
        self.s_sock.settimeout(5)
        self.c_sock.settimeout(5)
        self.server_error = None
        self.logged_in_user = None

        self.client_mtp = SiFT_MTP(self.c_sock, role="client", server_pubkey=pubkey)
        self.client_login = SiFT_LOGIN(self.client_mtp)
        self._server_privkey = privkey

    def _server_run(self):
        try:
            mtp = SiFT_MTP(self.s_sock, role="server", server_privkey=self._server_privkey,
                           monitor=self.monitor, peer_name="test")
            loginp = SiFT_LOGIN(mtp, guard=self.guard)
            loginp.set_server_users(self._users)
            user, _, _ = loginp.handle_login_server()
            self.logged_in_user = user
            cmdp = SiFT_CMD(mtp)
            cmdp.set_server_rootdir(self._rootdir)
            cmdp.set_user_rootdir(self._users[user]["rootdir"])
            while True:
                cmdp.receive_command()
        except Exception as e:  # noqa: BLE001 -- surfaced to the test via server_error
            self.server_error = e

    def login(self, username: str, password: str) -> SiFT_CMD:
        self._thread = threading.Thread(target=self._server_run, daemon=True)
        self._thread.start()
        self.client_login.handle_login_client(username, password)
        return SiFT_CMD(self.client_mtp)

    def close(self):
        self.c_sock.close()
        self.s_sock.close()


@pytest.fixture
def loopback(rsa_keys, users, tmp_path):
    rootdir = str(tmp_path) + os.sep
    for u in users:
        os.makedirs(os.path.join(rootdir, users[u]["rootdir"]), exist_ok=True)
    sessions = []

    def _make(monitor=None):
        s = LoopbackSession(rsa_keys, users, rootdir, monitor=monitor)
        sessions.append(s)
        return s

    yield _make
    for s in sessions:
        s.close()
