"""Tests for the MTP layer: framing, AEAD, fail-closed behaviour, replay defence."""

from __future__ import annotations

import os

import pytest

from conftest import FakeSocket, paired_keyed_mtps
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


def _transmit(sender: SiFT_MTP, receiver: SiFT_MTP, msg_type: bytes, payload: bytes) -> bytes:
    """Send one message and return the wire bytes (also loaded into the receiver)."""
    sender.send_msg(msg_type, payload)
    wire = sender.peer_socket.sent
    sender.peer_socket.sent = b""
    receiver.peer_socket.inbox = wire
    return wire


def test_header_roundtrip():
    mtp = SiFT_MTP(FakeSocket(), role="client")
    hdr = mtp.msg_hdr_ver + mtp.type_command_req + (42).to_bytes(2, "big") + \
        (7).to_bytes(2, "big") + os.urandom(6) + b"\x00\x00"
    parsed = mtp.parse_msg_header(hdr)
    assert parsed["ver"] == mtp.msg_hdr_ver
    assert parsed["typ"] == mtp.type_command_req
    assert int.from_bytes(parsed["len"], "big") == 42
    assert int.from_bytes(parsed["sqn"], "big") == 7


def test_aead_roundtrip():
    sender, receiver = paired_keyed_mtps()
    payload = b"hello secure world"
    _transmit(sender, receiver, sender.type_command_req, payload)
    typ, got = receiver.receive_msg()
    assert typ == receiver.type_command_req
    assert got == payload


def test_tampered_ciphertext_fails_closed():
    sender, receiver = paired_keyed_mtps()
    _transmit(sender, receiver, sender.type_command_req, b"transfer $1000000")
    wire = bytearray(receiver.peer_socket.inbox)
    # Flip a bit in the ciphertext region (after the 16-byte header).
    wire[20] ^= 0x01
    receiver.peer_socket.inbox = bytes(wire)
    with pytest.raises(SiFT_MTP_Error, match="MAC verification failed"):
        receiver.receive_msg()


def test_tampered_header_aad_fails_closed():
    sender, receiver = paired_keyed_mtps()
    _transmit(sender, receiver, sender.type_command_req, b"payload")
    wire = bytearray(receiver.peer_socket.inbox)
    # The header is authenticated as AAD; flipping the reserved byte must be caught.
    wire[15] ^= 0x01
    receiver.peer_socket.inbox = bytes(wire)
    with pytest.raises(SiFT_MTP_Error):
        receiver.receive_msg()


def test_replayed_or_old_sequence_rejected():
    sender, receiver = paired_keyed_mtps()
    first = _transmit(sender, receiver, sender.type_command_req, b"one")
    receiver.receive_msg()  # accept sqn=1
    # Replay the exact same bytes: sqn=1 is no longer > last-seen (1).
    receiver.peer_socket.inbox = first
    with pytest.raises(SiFT_MTP_Error, match="sequence number is too old"):
        receiver.receive_msg()


def test_wrong_key_fails_closed():
    sender, receiver = paired_keyed_mtps()
    receiver._recv_key = os.urandom(32)  # attacker/mismatched key
    _transmit(sender, receiver, sender.type_command_req, b"secret")
    with pytest.raises(SiFT_MTP_Error, match="MAC verification failed"):
        receiver.receive_msg()


def test_directional_keys_are_distinct():
    client = SiFT_MTP(FakeSocket(), role="client")
    server = SiFT_MTP(FakeSocket(), role="server")
    k_c2s, k_s2c = os.urandom(32), os.urandom(32)
    client.set_session_keys(k_c2s, k_s2c)
    server.set_session_keys(k_c2s, k_s2c)
    # Client sends with c2s; server receives with c2s. And vice versa.
    assert client._send_key == server._recv_key == k_c2s
    assert client._recv_key == server._send_key == k_s2c
    assert client._send_key != client._recv_key


def test_unknown_type_and_version_rejected():
    mtp = SiFT_MTP(FakeSocket(), role="server")
    # Build a header with a bogus type.
    bad = mtp.msg_hdr_ver + b"\xff\xff" + (16).to_bytes(2, "big") + \
        (1).to_bytes(2, "big") + os.urandom(6) + b"\x00\x00"
    mtp.peer_socket.inbox = bad
    with pytest.raises(SiFT_MTP_Error, match="Unknown message type"):
        mtp.receive_msg()
