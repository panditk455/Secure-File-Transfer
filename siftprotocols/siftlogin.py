"""SiFT Login Protocol -- authentication and session-key establishment.

The login exchange does three jobs at once:

1. **Authenticates the user** with PBKDF2-HMAC-SHA256 (per-user 16-byte salt,
   100,000 iterations). Passwords are never stored or compared in the clear.
2. **Establishes fresh session keys.** The client's temporary key ``tk`` is
   RSA-OAEP-wrapped to the server (handled in ``siftmtp``); both sides then mix a
   client random and a server random through HKDF-SHA256 to derive two
   *directional* AES keys (``k_c2s`` and ``k_s2c``).
3. **Resists replay and online guessing.** A timestamp window, a request-hash
   replay cache, and a per-user brute-force lockout (all in ``LoginGuard``, shared
   across connections) push back on the obvious active attacks.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from os import urandom

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2

from . import monitoring
from .siftmtp import SiFT_MTP, SiFT_MTP_Error

# HKDF context labels give the two directions independent keys from one secret.
_CTX_C2S = b"SiFT v1.0 client-to-server"
_CTX_S2C = b"SiFT v1.0 server-to-client"


class SiFT_LOGIN_Error(Exception):
    def __init__(self, err_msg: str) -> None:
        self.err_msg = err_msg
        super().__init__(err_msg)


class LoginGuard:
    """Server-wide, thread-safe defence against replay and online password guessing.

    Shared across all client connections so an attacker cannot dodge the limits by
    opening a fresh socket for each attempt.
    """

    def __init__(
        self,
        monitor: monitoring.SecurityMonitor | None = None,
        max_failures: int = 5,
        lockout_s: float = 60.0,
        replay_window_s: float = 2.0,
    ) -> None:
        self._lock = threading.Lock()
        self._monitor = monitor
        self._max_failures = max_failures
        self._lockout_s = lockout_s
        self._replay_window_s = replay_window_s
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._seen_requests: dict[bytes, float] = {}

    def check_not_replay(self, request_hash: bytes) -> None:
        now = time.time()
        with self._lock:
            # Prune expired entries, then check.
            expired = [h for h, t in self._seen_requests.items() if now - t > self._replay_window_s]
            for h in expired:
                del self._seen_requests[h]
            if request_hash in self._seen_requests:
                if self._monitor:
                    self._monitor.record(monitoring.EVT_REPLAY_ATTEMPT, level=monitoring.WARNING,
                                          request_hash=request_hash.hex()[:16])
                raise SiFT_LOGIN_Error("Duplicate login request detected (possible replay)")
            self._seen_requests[request_hash] = now

    def assert_not_locked(self, username: str) -> None:
        now = time.time()
        with self._lock:
            until = self._locked_until.get(username, 0.0)
            if now < until:
                if self._monitor:
                    self._monitor.record(monitoring.EVT_RATE_LIMITED, level=monitoring.WARNING,
                                          username=username, retry_in_s=round(until - now, 1))
                raise SiFT_LOGIN_Error("Account temporarily locked due to repeated failed logins")

    def record_failure(self, username: str) -> None:
        now = time.time()
        with self._lock:
            window = self._failures[username]
            window.append(now)
            while window and now - window[0] > self._lockout_s:
                window.popleft()
            if len(window) >= self._max_failures:
                self._locked_until[username] = now + self._lockout_s
                window.clear()

    def record_success(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username, None)
            self._locked_until.pop(username, None)


class SiFT_LOGIN:
    def __init__(self, mtp: SiFT_MTP, guard: LoginGuard | None = None) -> None:
        # --------- CONSTANTS ------------
        self.delimiter = "\n"
        self.coding = "utf-8"
        self.timestamp_window_ns = 2 * 10**9  # +/- 2 seconds
        # --------- STATE ------------
        self.mtp = mtp
        self.guard = guard
        self.server_users: dict | None = None

    def set_server_users(self, users: dict) -> None:
        self.server_users = users

    # -- (de)serialisation ---------------------------------------------------

    def build_login_req(self, s: dict) -> bytes:
        parts = [str(s["timestamp"]), s["username"], s["password"], s["client_random"]]
        return self.delimiter.join(parts).encode(self.coding)

    def parse_login_req(self, payload: bytes) -> dict:
        fields = payload.decode(self.coding).split(self.delimiter)
        if len(fields) != 4:
            raise SiFT_LOGIN_Error("Invalid login request format")
        return {
            "timestamp": fields[0],
            "username": fields[1],
            "password": fields[2],
            "client_random": fields[3],
        }

    def build_login_res(self, s: dict) -> bytes:
        parts = [s["request_hash"].hex(), s["server_random"].hex()]
        return self.delimiter.join(parts).encode(self.coding)

    def parse_login_res(self, payload: bytes) -> dict:
        fields = payload.decode(self.coding).split(self.delimiter)
        if len(fields) != 2:
            raise SiFT_LOGIN_Error("Invalid login response format")
        return {
            "request_hash": bytes.fromhex(fields[0]),
            "server_random": bytes.fromhex(fields[1]),
        }

    # -- helpers -------------------------------------------------------------

    def check_password(self, pwd: str, usr_struct: dict) -> bool:
        pwdhash = PBKDF2(
            pwd, usr_struct["salt"], len(usr_struct["pwdhash"]),
            count=usr_struct["icount"], hmac_hash_module=SHA256,
        )
        return pwdhash == usr_struct["pwdhash"]

    def validate_timestamp(self, received_timestamp: str) -> None:
        now_ns = time.time_ns()
        try:
            recv_ns = int(received_timestamp)
        except ValueError:
            raise SiFT_LOGIN_Error("Malformed timestamp in login request")
        if abs(now_ns - recv_ns) > self.timestamp_window_ns:
            raise SiFT_LOGIN_Error("Timestamp outside acceptable window")

    @staticmethod
    def _derive_keys(client_random: bytes, server_random: bytes, request_hash: bytes) -> tuple[bytes, bytes]:
        ikm = client_random + server_random
        k_c2s = HKDF(master=ikm, key_len=32, salt=request_hash, hashmod=SHA256, context=_CTX_C2S)
        k_s2c = HKDF(master=ikm, key_len=32, salt=request_hash, hashmod=SHA256, context=_CTX_S2C)
        return k_c2s, k_s2c

    def _monitor(self, event: str, level: str = monitoring.INFO, **fields) -> None:
        if self.mtp.monitor:
            self.mtp.monitor.record(event, level=level, peer=self.mtp.peer_name, **fields)

    # -- server side ---------------------------------------------------------

    def handle_login_server(self) -> tuple[str, bytes, bytes]:
        if not self.server_users:
            raise SiFT_LOGIN_Error("User database is required for handling login at server")

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to receive login request --> " + e.err_msg)

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error("Login request expected, but received something else")

        request_hash = SHA256.new(msg_payload).digest()
        if self.guard:
            self.guard.check_not_replay(request_hash)

        login_req = self.parse_login_req(msg_payload)
        self.validate_timestamp(login_req["timestamp"])

        username = login_req["username"]
        if self.guard:
            self.guard.assert_not_locked(username)

        authenticated = (
            username in self.server_users
            and self.check_password(login_req["password"], self.server_users[username])
        )
        if not authenticated:
            if self.guard:
                self.guard.record_failure(username)
            self._monitor(monitoring.EVT_LOGIN_FAILURE, level=monitoring.WARNING, username=username)
            raise SiFT_LOGIN_Error("Login failed: unknown user or bad password")

        if self.guard:
            self.guard.record_success(username)

        server_random = urandom(16)
        client_random = bytes.fromhex(login_req["client_random"])

        # The server continues the client's sequence so the login response uses a
        # different sequence number than the request even though both use ``tk``.
        self.mtp.send_sequence_num = self.mtp.received_sequence_num
        try:
            self.mtp.send_msg(
                self.mtp.type_login_res,
                self.build_login_res({"request_hash": request_hash, "server_random": server_random}),
            )
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to send login response --> " + e.err_msg)

        k_c2s, k_s2c = self._derive_keys(client_random, server_random, request_hash)
        self.mtp.set_session_keys(k_c2s, k_s2c)
        self._monitor(monitoring.EVT_LOGIN_SUCCESS, username=username)
        return username, k_c2s, k_s2c

    # -- client side ---------------------------------------------------------

    def handle_login_client(self, username: str, password: str) -> tuple[bytes, bytes]:
        client_random = urandom(16)
        login_req = {
            "timestamp": str(time.time_ns()),
            "username": username,
            "password": password,
            "client_random": client_random.hex(),
        }
        msg_payload = self.build_login_req(login_req)

        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to send login request --> " + e.err_msg)

        request_hash = SHA256.new(msg_payload).digest()

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to receive login response --> " + e.err_msg)

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error("Login response expected, but received something else")

        login_res = self.parse_login_res(msg_payload)
        if login_res["request_hash"] != request_hash:
            raise SiFT_LOGIN_Error("Verification of login response failed")

        k_c2s, k_s2c = self._derive_keys(client_random, login_res["server_random"], request_hash)
        self.mtp.set_session_keys(k_c2s, k_s2c)
        return k_c2s, k_s2c
