"""SiFT Message Transfer Protocol (MTP) -- the secure transport layer.

Every SiFT message is a 16-byte header followed by an AES-256-GCM ciphertext and
a 12-byte authentication tag (the login request additionally carries a 256-byte
RSA-OAEP-encrypted temporary key). GCM gives us confidentiality *and* integrity
in one pass, with the header bound in as associated data so it cannot be altered.

Design decisions worth calling out (see ``SECURITY_ANALYSIS.md`` / the v1.0 spec):

* **AEAD, fail-closed.** A failed tag verification raises ``SiFT_MTP_Error`` and
  emits a ``mac_failure`` security event. The protocol never returns unverified
  plaintext -- authenticated encryption must fail closed.
* **Directional keys.** After login, the two directions use *different* keys
  (``k_c2s`` for client->server, ``k_s2c`` for server->client). Combined with the
  per-message sequence number in the GCM nonce, this makes a nonce collision
  across the two directions impossible.
* **No secret leakage by default.** An optional ``tracer`` callback receives
  structured per-message metadata (header fields, ciphertext, MAC, verify status)
  for the demo's wire panel, but key material is reduced to a short fingerprint
  unless the tracer was explicitly created to reveal it.
"""

from __future__ import annotations

from os import urandom
from typing import Any, Callable

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from . import monitoring

# Human-readable names for message type codes (used by tracer/monitor output).
_TYPE_NAMES = {
    b"\x00\x00": "login_req",
    b"\x00\x10": "login_res",
    b"\x01\x00": "command_req",
    b"\x01\x10": "command_res",
    b"\x02\x00": "upload_req_0",
    b"\x02\x01": "upload_req_1",
    b"\x02\x10": "upload_res",
    b"\x03\x00": "dnload_req",
    b"\x03\x10": "dnload_res_0",
    b"\x03\x11": "dnload_res_1",
}


def _fingerprint(key: bytes) -> str:
    """A short, non-reversible label for a key (safe to log)."""
    return SHA256.new(key).hexdigest()[:8]


class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg: str) -> None:
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_MTP:
    def __init__(
        self,
        peer_socket,
        role: str = "client",
        server_pubkey: RSA.RsaKey | None = None,
        server_privkey: RSA.RsaKey | None = None,
        tracer: Callable[[dict[str, Any]], None] | None = None,
        monitor: monitoring.SecurityMonitor | None = None,
        peer_name: str = "",
    ) -> None:
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b"\x01\x00"
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
        self.size_mac = 12
        self.size_etk = 256  # RSA-2048 ciphertext
        self.type_login_req = b"\x00\x00"
        self.type_login_res = b"\x00\x10"
        self.type_command_req = b"\x01\x00"
        self.type_command_res = b"\x01\x10"
        self.type_upload_req_0 = b"\x02\x00"
        self.type_upload_req_1 = b"\x02\x01"
        self.type_upload_res = b"\x02\x10"
        self.type_dnload_req = b"\x03\x00"
        self.type_dnload_res_0 = b"\x03\x10"
        self.type_dnload_res_1 = b"\x03\x11"
        self.msg_types = (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
            self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1,
        )
        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.role = role
        self.server_pubkey = server_pubkey
        self.server_privkey = server_privkey
        self.tracer = tracer
        self.monitor = monitor
        self.peer_name = peer_name

        self.tk: bytes | None = None            # temporary key (login only)
        self._send_key: bytes | None = None     # directional key for our sends
        self._recv_key: bytes | None = None     # directional key for our receives
        self.send_sequence_num = 0
        self.received_sequence_num = 0

    # -- key management ------------------------------------------------------

    def set_session_keys(self, k_c2s: bytes, k_s2c: bytes) -> None:
        """Install the two directional keys derived during login."""
        if self.role == "client":
            self._send_key, self._recv_key = k_c2s, k_s2c
        else:
            self._send_key, self._recv_key = k_s2c, k_c2s

    def _trace(self, **fields: Any) -> None:
        if self.tracer:
            try:
                self.tracer(fields)
            except Exception:
                pass

    # -- header --------------------------------------------------------------

    def parse_msg_header(self, msg_hdr: bytes) -> dict[str, bytes]:
        i = 0
        parsed: dict[str, bytes] = {}
        parsed["ver"], i = msg_hdr[i:i + 2], i + 2
        parsed["typ"], i = msg_hdr[i:i + 2], i + 2
        parsed["len"], i = msg_hdr[i:i + 2], i + 2
        parsed["sqn"], i = msg_hdr[i:i + 2], i + 2
        parsed["rnd"], i = msg_hdr[i:i + 6], i + 6
        parsed["rsv"], i = msg_hdr[i:i + 2], i + 2
        return parsed

    # -- socket I/O ----------------------------------------------------------

    def receive_bytes(self, n: int) -> bytes:
        received = b""
        while len(received) < n:
            try:
                chunk = self.peer_socket.recv(n - len(received))
            except OSError:
                raise SiFT_MTP_Error("Unable to receive via peer socket")
            if not chunk:
                raise SiFT_MTP_Error("Connection with peer is broken")
            received += chunk
        return received

    def send_bytes(self, bytes_to_send: bytes) -> None:
        try:
            self.peer_socket.sendall(bytes_to_send)
        except OSError:
            raise SiFT_MTP_Error("Unable to send via peer socket")

    # -- receive -------------------------------------------------------------

    def receive_msg(self) -> tuple[bytes, bytes]:
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to receive message header --> " + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error("Incomplete message header received")

        parsed = self.parse_msg_header(msg_hdr)

        if parsed["ver"] != self.msg_hdr_ver:
            self._monitor(monitoring.EVT_PROTOCOL_ERROR, level=monitoring.WARNING,
                          detail="unsupported version", ver=parsed["ver"].hex())
            raise SiFT_MTP_Error("Unsupported version found in message header")

        if parsed["typ"] not in self.msg_types:
            self._monitor(monitoring.EVT_PROTOCOL_ERROR, level=monitoring.WARNING,
                          detail="unknown message type", typ=parsed["typ"].hex())
            raise SiFT_MTP_Error("Unknown message type found in message header")

        msg_len = int.from_bytes(parsed["len"], byteorder="big")
        if msg_len < self.size_msg_hdr:
            raise SiFT_MTP_Error("Message length in header is too small")

        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to receive message body --> " + e.err_msg)

        # Replay / reordering defence: sequence numbers must strictly increase.
        received_sqn = int.from_bytes(parsed["sqn"], byteorder="big")
        if received_sqn <= self.received_sequence_num:
            self._monitor(monitoring.EVT_SEQUENCE_VIOLATION, level=monitoring.WARNING,
                          got=received_sqn, expected_gt=self.received_sequence_num,
                          typ=_TYPE_NAMES.get(parsed["typ"], "?"))
            raise SiFT_MTP_Error("Message sequence number is too old")

        etk = b""
        if parsed["typ"] == self.type_login_req:
            if self.role != "server" or self.server_privkey is None:
                raise SiFT_MTP_Error("Received a login request but no private key is configured")
            if len(msg_body) < self.size_etk + self.size_mac:
                raise SiFT_MTP_Error("Login request too short")
            etk = msg_body[-self.size_etk:]
            msg_body = msg_body[:-self.size_etk]
            try:
                cipher_rsa = PKCS1_OAEP.new(self.server_privkey, hashAlgo=SHA256)
                key = cipher_rsa.decrypt(etk)
            except ValueError:
                self._monitor(monitoring.EVT_PROTOCOL_ERROR, level=monitoring.WARNING,
                              detail="RSA-OAEP decryption of temporary key failed")
                raise SiFT_MTP_Error("Unable to decrypt temporary key")
            self.tk = key
        elif parsed["typ"] == self.type_login_res:
            key = self.tk
        else:
            key = self._recv_key

        if key is None:
            raise SiFT_MTP_Error("No key available to decrypt message (out-of-order handshake?)")

        if len(msg_body) < self.size_mac:
            raise SiFT_MTP_Error("Message body shorter than authentication tag")
        msg_mac = msg_body[-self.size_mac:]
        ciphertext = msg_body[:-self.size_mac]

        nonce = parsed["sqn"] + parsed["rnd"]  # 2 + 6 = 8 bytes
        gcm = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
        gcm.update(msg_hdr)  # header is authenticated (AAD) but not encrypted
        try:
            plaintext = gcm.decrypt_and_verify(ciphertext, msg_mac)
        except ValueError:
            # Fail CLOSED: reject, never return unauthenticated data.
            self._monitor(monitoring.EVT_MAC_FAILURE, level=monitoring.ALERT,
                          typ=_TYPE_NAMES.get(parsed["typ"], "?"), sqn=received_sqn)
            self._trace(direction="recv", verified=False,
                        type=_TYPE_NAMES.get(parsed["typ"], "?"),
                        header=msg_hdr.hex(), sqn=received_sqn,
                        nonce=nonce.hex(), ciphertext=ciphertext.hex(),
                        mac=msg_mac.hex(), key_fpr=_fingerprint(key))
            raise SiFT_MTP_Error("MAC verification failed")

        # Only commit the sequence number once the message is authenticated.
        self.received_sequence_num = received_sqn

        self._trace(direction="recv", verified=True,
                    type=_TYPE_NAMES.get(parsed["typ"], "?"),
                    header=msg_hdr.hex(), sqn=received_sqn, rnd=parsed["rnd"].hex(),
                    nonce=nonce.hex(), ciphertext=ciphertext.hex(),
                    mac=msg_mac.hex(), key_fpr=_fingerprint(key),
                    plaintext_len=len(plaintext), etk=etk.hex() if etk else None)

        return parsed["typ"], plaintext

    # -- send ----------------------------------------------------------------

    def send_msg(self, msg_type: bytes, msg_payload: bytes) -> None:
        authtag_length = self.size_mac
        header_length = self.size_msg_hdr

        if msg_type == self.type_login_req:
            msg_length = header_length + len(msg_payload) + authtag_length + self.size_etk
        else:
            msg_length = header_length + len(msg_payload) + authtag_length

        # Build the header. Sequence number strictly increases per sender.
        self.send_sequence_num += 1
        sqn_field = self.send_sequence_num.to_bytes(2, byteorder="big")
        rnd_field = urandom(6)
        header = (
            self.msg_hdr_ver + msg_type + msg_length.to_bytes(2, byteorder="big")
            + sqn_field + rnd_field + b"\x00\x00"
        )

        etk = b""
        if msg_type == self.type_login_req:
            if self.role != "client" or self.server_pubkey is None:
                raise SiFT_MTP_Error("Cannot send login request without the server public key")
            self.tk = urandom(32)  # fresh 256-bit temporary key per session
            key = self.tk
            cipher_rsa = PKCS1_OAEP.new(self.server_pubkey, hashAlgo=SHA256)
            etk = cipher_rsa.encrypt(self.tk)
        elif msg_type == self.type_login_res:
            key = self.tk
        else:
            key = self._send_key

        if key is None:
            raise SiFT_MTP_Error("No key available to encrypt message (out-of-order handshake?)")

        nonce = sqn_field + rnd_field
        gcm = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
        gcm.update(header)
        ciphertext, mac = gcm.encrypt_and_digest(msg_payload)

        full_message = header + ciphertext + mac + etk

        self._trace(direction="send", verified=True,
                    type=_TYPE_NAMES.get(msg_type, "?"),
                    header=header.hex(), sqn=self.send_sequence_num, rnd=rnd_field.hex(),
                    nonce=nonce.hex(), ciphertext=ciphertext.hex(),
                    mac=mac.hex(), key_fpr=_fingerprint(key),
                    plaintext_len=len(msg_payload), etk=etk.hex() if etk else None)

        try:
            self.send_bytes(full_message)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to send message to peer --> " + e.err_msg)

    # -- monitoring helper ---------------------------------------------------

    def _monitor(self, event: str, level: str = monitoring.INFO, **fields: Any) -> None:
        if self.monitor:
            self.monitor.record(event, level=level, peer=self.peer_name, **fields)
