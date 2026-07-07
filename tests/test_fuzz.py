"""Property-based fuzzing of the SiFT parsers.

Malformed input from the network must never crash the protocol with an unexpected
exception type -- parsers should either succeed or raise a *handled* protocol
error. These tests throw random and structured garbage at the header and payload
parsers and assert they never leak an uncaught surprise (and never hang).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import FakeSocket
from siftprotocols.siftcmd import SiFT_CMD
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

_HANDLED = (SiFT_MTP_Error, SiFT_LOGIN_Error, ValueError, IndexError, UnicodeDecodeError)


@given(raw=st.binary(min_size=0, max_size=64))
@settings(max_examples=300)
def test_parse_msg_header_never_crashes(raw):
    mtp = SiFT_MTP(FakeSocket(), role="server")
    # parse_msg_header slices fixed offsets; on short input it simply returns short
    # fields. It must not raise -- validation happens in receive_msg.
    parsed = mtp.parse_msg_header(raw)
    assert set(parsed) == {"ver", "typ", "len", "sqn", "rnd", "rsv"}


@given(raw=st.binary(min_size=0, max_size=256))
@settings(max_examples=300)
def test_receive_msg_rejects_garbage_cleanly(raw):
    mtp = SiFT_MTP(FakeSocket(), role="server")
    mtp.peer_socket.inbox = raw
    try:
        mtp.receive_msg()
    except _HANDLED:
        pass  # expected: handled protocol/parse error


@given(raw=st.binary(min_size=0, max_size=128))
@settings(max_examples=300)
def test_parse_login_req_handles_garbage(raw):
    lp = SiFT_LOGIN(SiFT_MTP(FakeSocket(), role="server"))
    try:
        lp.parse_login_req(raw)
    except _HANDLED:
        pass


@given(raw=st.binary(min_size=0, max_size=128))
@settings(max_examples=300)
def test_parse_command_req_handles_garbage(raw):
    c = SiFT_CMD(SiFT_MTP(FakeSocket(), role="server"))
    try:
        c.parse_command_req(raw)
    except _HANDLED:
        pass


@given(
    fields=st.lists(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=20),
                    min_size=0, max_size=8)
)
@settings(max_examples=200)
def test_parse_login_req_structured(fields):
    lp = SiFT_LOGIN(SiFT_MTP(FakeSocket(), role="server"))
    payload = "\n".join(fields).encode("utf-8")
    try:
        lp.parse_login_req(payload)
    except _HANDLED:
        pass
