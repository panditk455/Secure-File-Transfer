"""Tests for the command layer: name allowlist, traversal defence, and full round-trips."""

from __future__ import annotations

import os

from Crypto.Hash import SHA256

from conftest import FakeSocket
from siftprotocols.siftcmd import SiFT_CMD
from siftprotocols.siftmtp import SiFT_MTP
from siftprotocols.siftupl import SiFT_UPL
from siftprotocols.siftdnl import SiFT_DNL


def _cmd():
    return SiFT_CMD(SiFT_MTP(FakeSocket(), role="server"))


def test_check_fdname_allowlist():
    c = _cmd()
    assert c.check_fdname("report.txt") is True
    assert c.check_fdname("my-file_2.dat") is True
    assert c.check_fdname("") is False
    assert c.check_fdname(".hidden") is False
    assert c.check_fdname("..") is False
    assert c.check_fdname("a/b") is False
    assert c.check_fdname("../etc/passwd") is False
    assert c.check_fdname("space name") is False


def test_command_req_res_serialisation():
    c = _cmd()
    for req in (
        {"command": "pwd"},
        {"command": "chd", "param_1": "docs"},
        {"command": "upl", "param_1": "a.txt", "param_2": 10, "param_3": b"\x01" * 32},
    ):
        assert c.parse_command_req(c.build_command_req(req)) == req


def test_pwd_ls_mkd_cd_roundtrip(loopback):
    session = loopback()
    cmdp = session.login("alice", "aaa")

    assert cmdp.send_command({"command": "pwd"})["result_2"] == "/"
    assert cmdp.send_command({"command": "mkd", "param_1": "docs"})["result_1"] == "success"
    assert cmdp.send_command({"command": "chd", "param_1": "docs"})["result_1"] == "success"
    assert cmdp.send_command({"command": "pwd"})["result_2"] == "docs/"


def test_traversal_is_blocked_and_flagged(loopback):
    monitor_events = []
    session = loopback()
    cmdp = session.login("alice", "aaa")

    res = cmdp.send_command({"command": "mkd", "param_1": "../escape"})
    assert res["result_1"] == "failure"

    res = cmdp.send_command({"command": "chd", "param_1": ".."})  # already at root
    assert res["result_1"] == "failure"

    import time
    time.sleep(0.2)
    events = [e["event"] for e in session.monitor.events()]
    assert "traversal_attempt" in events
    assert any(a["rule"] == "path_traversal" for a in session.monitor.alerts())


def test_upload_download_roundtrip_with_hash(loopback, tmp_path):
    session = loopback()
    cmdp = session.login("alice", "aaa")

    src = tmp_path / "payload.bin"
    data = os.urandom(3000)  # spans multiple 1024-byte fragments
    src.write_bytes(data)

    file_hash = SHA256.new(data).digest()
    res = cmdp.send_command({"command": "upl", "param_1": "payload.bin",
                             "param_2": len(data), "param_3": file_hash})
    assert res["result_1"] == "accept"
    SiFT_UPL(session.client_mtp).handle_upload_client(str(src))  # raises on hash mismatch

    res = cmdp.send_command({"command": "dnl", "param_1": "payload.bin"})
    assert res["result_1"] == "accept"
    assert res["result_2"] == len(data)
    assert res["result_3"] == file_hash

    dst = tmp_path / "roundtrip.bin"
    got_hash = SiFT_DNL(session.client_mtp).handle_download_client(str(dst))
    assert got_hash == file_hash
    assert dst.read_bytes() == data


def test_oversize_upload_rejected(loopback):
    session = loopback()
    cmdp = session.login("alice", "aaa")
    res = cmdp.send_command({"command": "upl", "param_1": "big.bin",
                             "param_2": 2**20, "param_3": b"\x00" * 32})
    assert res["result_1"] == "reject"
