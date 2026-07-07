"""SiFT Command Protocol -- the file-operation layer that runs over the MTP.

Supports ``pwd / lst / chd / mkd / del / upl / dnl``. Every user is confined to
their own root directory. Confinement is enforced by two independent checks:

* ``check_fdname`` -- an allowlist that rejects empty names, names beginning with
  ``.`` (blocks ``..``), and anything outside ``[A-Za-z0-9-_.]`` (blocks ``/``).
* ``_resolve`` -- a defence-in-depth ``realpath`` containment check, so even if a
  name slipped past the allowlist the resolved path must still live under the
  user root or the operation is refused.
"""

from __future__ import annotations

import os
from base64 import b64decode, b64encode

from Crypto.Hash import SHA256

from . import monitoring
from .siftmtp import SiFT_MTP, SiFT_MTP_Error
from .siftdnl import SiFT_DNL, SiFT_DNL_Error
from .siftupl import SiFT_UPL, SiFT_UPL_Error


class SiFT_CMD_Error(Exception):
    def __init__(self, err_msg: str) -> None:
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_CMD:
    def __init__(self, mtp: SiFT_MTP) -> None:
        # --------- CONSTANTS ------------
        self.delimiter = "\n"
        self.coding = "utf-8"
        self.cmd_pwd = "pwd"
        self.cmd_lst = "lst"
        self.cmd_chd = "chd"
        self.cmd_mkd = "mkd"
        self.cmd_del = "del"
        self.cmd_upl = "upl"
        self.cmd_dnl = "dnl"
        self.commands = (self.cmd_pwd, self.cmd_lst, self.cmd_chd,
                         self.cmd_mkd, self.cmd_del, self.cmd_upl, self.cmd_dnl)
        self.res_success = "success"
        self.res_failure = "failure"
        self.res_accept = "accept"
        self.res_reject = "reject"
        # --------- STATE ------------
        self.mtp = mtp
        self.server_rootdir: str | None = None
        self.user_rootdir: str | None = None
        self.current_dir: list[str] = []
        self.filesize_limit = 2**16

    def set_server_rootdir(self, server_rootdir: str) -> None:
        self.server_rootdir = server_rootdir

    def set_user_rootdir(self, user_rootdir: str) -> None:
        self.user_rootdir = user_rootdir

    def set_filesize_limit(self, limit: int) -> None:
        self.filesize_limit = limit

    # -- (de)serialisation ---------------------------------------------------

    def build_command_req(self, s: dict) -> bytes:
        out = s["command"]
        if s["command"] in (self.cmd_chd, self.cmd_mkd, self.cmd_del, self.cmd_dnl):
            out += self.delimiter + s["param_1"]
        elif s["command"] == self.cmd_upl:
            out += self.delimiter + s["param_1"]
            out += self.delimiter + str(s["param_2"])
            out += self.delimiter + s["param_3"].hex()
        return out.encode(self.coding)

    def parse_command_req(self, cmd_req: bytes) -> dict:
        f = cmd_req.decode(self.coding).split(self.delimiter)
        s = {"command": f[0]}
        if s["command"] in (self.cmd_chd, self.cmd_mkd, self.cmd_del, self.cmd_dnl):
            s["param_1"] = f[1]
        elif s["command"] == self.cmd_upl:
            s["param_1"] = f[1]
            s["param_2"] = int(f[2])
            s["param_3"] = bytes.fromhex(f[3])
        return s

    def build_command_res(self, s: dict) -> bytes:
        out = s["command"] + self.delimiter + s["request_hash"].hex() + self.delimiter + s["result_1"]
        if s["command"] == self.cmd_pwd:
            out += self.delimiter + s["result_2"]
        elif s["command"] == self.cmd_lst:
            if s["result_1"] == self.res_failure:
                out += self.delimiter + s["result_2"]
            else:
                out += self.delimiter + b64encode(s["result_2"].encode(self.coding)).decode(self.coding)
        elif s["command"] in (self.cmd_chd, self.cmd_mkd, self.cmd_del):
            if s["result_1"] == self.res_failure:
                out += self.delimiter + s["result_2"]
        elif s["command"] == self.cmd_upl:
            if s["result_1"] == self.res_reject:
                out += self.delimiter + s["result_2"]
        elif s["command"] == self.cmd_dnl:
            if s["result_1"] == self.res_reject:
                out += self.delimiter + s["result_2"]
            else:
                out += self.delimiter + str(s["result_2"]) + self.delimiter + s["result_3"].hex()
        return out.encode(self.coding)

    def parse_command_res(self, cmd_res: bytes) -> dict:
        f = cmd_res.decode(self.coding).split(self.delimiter)
        s = {"command": f[0], "request_hash": bytes.fromhex(f[1]), "result_1": f[2]}
        if s["command"] == self.cmd_pwd:
            s["result_2"] = f[3]
        elif s["command"] == self.cmd_lst:
            if s["result_1"] == self.res_failure:
                s["result_2"] = f[3]
            else:
                s["result_2"] = b64decode(f[3]).decode(self.coding)
        elif s["command"] in (self.cmd_chd, self.cmd_mkd, self.cmd_del):
            if s["result_1"] == self.res_failure:
                s["result_2"] = f[3]
        elif s["command"] == self.cmd_upl:
            if s["result_1"] == self.res_reject:
                s["result_2"] = f[3]
        elif s["command"] == self.cmd_dnl:
            if s["result_1"] == self.res_reject:
                s["result_2"] = f[3]
            else:
                s["result_2"] = int(f[3])
                s["result_3"] = bytes.fromhex(f[4])
        return s

    # -- server: receive & dispatch -----------------------------------------

    def receive_command(self) -> None:
        if not self.server_rootdir or not self.user_rootdir:
            raise SiFT_CMD_Error("Root directory must be set before any file operations")

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error("Unable to receive command request --> " + e.err_msg)

        if msg_type != self.mtp.type_command_req:
            raise SiFT_CMD_Error("Command request expected, but received something else")

        request_hash = SHA256.new(msg_payload).digest()
        try:
            cmd_req = self.parse_command_req(msg_payload)
        except (ValueError, IndexError):
            raise SiFT_CMD_Error("Parsing command request failed")

        if cmd_req["command"] not in self.commands:
            raise SiFT_CMD_Error("Unexpected command received")

        cmd_res = self.exec_cmd(cmd_req, request_hash)

        try:
            self.mtp.send_msg(self.mtp.type_command_res, self.build_command_res(cmd_res))
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error("Unable to send command response --> " + e.err_msg)

        if cmd_res["command"] == self.cmd_upl and cmd_res["result_1"] == self.res_accept:
            self.exec_upl(cmd_req["param_1"])
        if cmd_res["command"] == self.cmd_dnl and cmd_res["result_1"] == self.res_accept:
            self.exec_dnl(cmd_req["param_1"])

    # -- client: send & receive ----------------------------------------------

    def send_command(self, cmd_req: dict) -> dict:
        try:
            self.mtp.send_msg(self.mtp.type_command_req, self.build_command_req(cmd_req))
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error("Unable to send command request --> " + e.err_msg)

        request_hash = SHA256.new(self.build_command_req(cmd_req)).digest()

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error("Unable to receive command response --> " + e.err_msg)

        if msg_type != self.mtp.type_command_res:
            raise SiFT_CMD_Error("Command response expected, but received something else")

        try:
            cmd_res = self.parse_command_res(msg_payload)
        except (ValueError, IndexError):
            raise SiFT_CMD_Error("Parsing command response failed")

        if cmd_res["request_hash"] != request_hash:
            raise SiFT_CMD_Error("Verification of command response failed")
        return cmd_res

    # -- path safety ---------------------------------------------------------

    def check_fdname(self, fdname: str) -> bool:
        """Allowlist for file/directory names. Blocks ``..``, ``/`` and hidden files."""
        if not fdname:
            return False
        if fdname[0] == ".":
            return False
        for c in fdname:
            if not c.isalnum() and c not in ("-", "_", "."):
                return False
        return True

    def _base_path(self) -> str:
        return os.path.join(self.server_rootdir, self.user_rootdir, *self.current_dir)

    def _resolve(self, name: str) -> str | None:
        """Return a contained absolute path for ``name`` or ``None`` if it escapes.

        Defence in depth: even if a name got past ``check_fdname``, the resolved
        real path must remain under the user's root directory.
        """
        user_root = os.path.realpath(os.path.join(self.server_rootdir, self.user_rootdir))
        candidate = os.path.realpath(os.path.join(self._base_path(), name))
        if candidate == user_root or candidate.startswith(user_root + os.sep):
            return candidate
        return None

    def _flag_traversal(self, name: str) -> None:
        if self.mtp.monitor:
            self.mtp.monitor.record(monitoring.EVT_TRAVERSAL_ATTEMPT, level=monitoring.WARNING,
                                    peer=self.mtp.peer_name, name=name)

    # -- command execution ---------------------------------------------------

    def exec_cmd(self, cmd_req: dict, request_hash: bytes) -> dict:
        res = {"command": cmd_req["command"], "request_hash": request_hash}
        command = cmd_req["command"]

        if command == self.cmd_pwd:
            res["result_1"] = self.res_success
            res["result_2"] = "/".join(self.current_dir) + "/"

        elif command == self.cmd_lst:
            path = self._base_path()
            if os.path.exists(path):
                entries = []
                with os.scandir(path) as it:
                    for f in it:
                        if f.name.startswith("."):
                            continue
                        entries.append(f.name + ("/" if f.is_dir() else ""))
                res["result_1"] = self.res_success
                res["result_2"] = "\n".join(entries)
            else:
                res["result_1"] = self.res_failure
                res["result_2"] = "Operation failed due to local error on server"

        elif command == self.cmd_chd:
            dirname = cmd_req["param_1"]
            if dirname == "..":
                if not self.current_dir:
                    res["result_1"] = self.res_failure
                    res["result_2"] = "Cannot change to directory outside of the user root directory"
                else:
                    self.current_dir = self.current_dir[:-1]
                    res["result_1"] = self.res_success
            elif not self.check_fdname(dirname):
                self._flag_traversal(dirname)
                res["result_1"] = self.res_failure
                res["result_2"] = "Directory name is empty, starts with . or contains unsupported characters"
            else:
                target = self._resolve(dirname)
                if target is None or not os.path.isdir(target):
                    if target is None:
                        self._flag_traversal(dirname)
                    res["result_1"] = self.res_failure
                    res["result_2"] = "Directory does not exist"
                else:
                    self.current_dir.append(dirname)
                    res["result_1"] = self.res_success

        elif command == self.cmd_mkd:
            dirname = cmd_req["param_1"]
            target = self._resolve(dirname) if self.check_fdname(dirname) else None
            if target is None:
                self._flag_traversal(dirname)
                res["result_1"] = self.res_failure
                res["result_2"] = "Directory name is empty, starts with . or contains unsupported characters"
            elif os.path.exists(target):
                res["result_1"] = self.res_failure
                res["result_2"] = "Directory already exists"
            else:
                try:
                    os.mkdir(target)
                    res["result_1"] = self.res_success
                except OSError:
                    res["result_1"] = self.res_failure
                    res["result_2"] = "Creating directory failed"

        elif command == self.cmd_del:
            fdname = cmd_req["param_1"]
            target = self._resolve(fdname) if self.check_fdname(fdname) else None
            if target is None:
                self._flag_traversal(fdname)
                res["result_1"] = self.res_failure
                res["result_2"] = "File or directory name is empty, starts with . or contains unsupported characters"
            elif not os.path.exists(target):
                res["result_1"] = self.res_failure
                res["result_2"] = "File or directory does not exist"
            else:
                try:
                    if os.path.isdir(target):
                        os.rmdir(target)
                    else:
                        os.remove(target)
                    res["result_1"] = self.res_success
                except OSError:
                    res["result_1"] = self.res_failure
                    res["result_2"] = "Removing file or directory failed"

        elif command == self.cmd_upl:
            filename = cmd_req["param_1"]
            filesize = cmd_req["param_2"]
            if not self.check_fdname(filename) or self._resolve(filename) is None:
                self._flag_traversal(filename)
                res["result_1"] = self.res_reject
                res["result_2"] = "File name is empty, starts with . or contains unsupported characters"
            elif filesize > self.filesize_limit:
                res["result_1"] = self.res_reject
                res["result_2"] = "File to be uploaded is too large"
            else:
                res["result_1"] = self.res_accept

        elif command == self.cmd_dnl:
            filename = cmd_req["param_1"]
            target = self._resolve(filename) if self.check_fdname(filename) else None
            if target is None:
                self._flag_traversal(filename)
                res["result_1"] = self.res_reject
                res["result_2"] = "File name is empty, starts with . or contains unsupported characters"
            elif not os.path.isfile(target):
                res["result_1"] = self.res_reject
                res["result_2"] = "File does not exist"
            else:
                hash_fn = SHA256.new()
                file_size = 0
                with open(target, "rb") as f:
                    while True:
                        chunk = f.read(1024)
                        if not chunk:
                            break
                        file_size += len(chunk)
                        hash_fn.update(chunk)
                res["result_1"] = self.res_accept
                res["result_2"] = file_size
                res["result_3"] = hash_fn.digest()

        return res

    def exec_upl(self, filename: str) -> None:
        target = self._resolve(filename) if self.check_fdname(filename) else None
        if target is None:
            raise SiFT_UPL_Error("File name is empty, starts with . or contains unsupported characters")
        SiFT_UPL(self.mtp).handle_upload_server(target)

    def exec_dnl(self, filename: str) -> None:
        target = self._resolve(filename) if self.check_fdname(filename) else None
        if target is None:
            raise SiFT_DNL_Error("File name is empty, starts with . or contains unsupported characters")
        if not os.path.isfile(target):
            raise SiFT_DNL_Error("File does not exist")
        SiFT_DNL(self.mtp).handle_download_server(target)
