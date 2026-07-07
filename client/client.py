#!/usr/bin/env python3
"""SiFT client -- an interactive shell for the secure file-transfer protocol.

    python client.py --host 127.0.0.1 --port 5150

On connect it prints the server public-key fingerprint. Pin this value (compare
it to the fingerprint printed by ``generate_keys.py``): SiFT trusts the server
key on first use, so a mismatch is how you would catch a man-in-the-middle.
"""

from __future__ import annotations

import argparse
import cmd
import getpass
import os
import socket
import sys

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error  # noqa: E402
from siftprotocols.siftdnl import SiFT_DNL, SiFT_DNL_Error  # noqa: E402
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error  # noqa: E402
from siftprotocols.siftmtp import SiFT_MTP  # noqa: E402
from siftprotocols.siftupl import SiFT_UPL, SiFT_UPL_Error  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


class SiFTShell(cmd.Cmd):
    intro = "Client shell for the SiFT protocol. Type help or ? to list commands.\n"
    prompt = "(sift) "

    def __init__(self, cmdp: SiFT_CMD, mtp: SiFT_MTP, sckt: socket.socket):
        super().__init__()
        self.cmdp = cmdp
        self.mtp = mtp
        self.sckt = sckt

    def _simple(self, command: str, arg: str | None = None) -> None:
        req = {"command": command}
        if arg is not None:
            req["param_1"] = arg.split(" ")[0]
        try:
            res = self.cmdp.send_command(req)
        except SiFT_CMD_Error as e:
            print("SiFT_CMD_Error: " + e.err_msg)
            return
        if res["result_1"] == self.cmdp.res_failure:
            print("Remote_Error: " + res["result_2"])
        elif "result_2" in res and res["result_2"]:
            print(res["result_2"])

    def do_pwd(self, arg):
        "Print current working directory on the server: pwd"
        self._simple(self.cmdp.cmd_pwd)

    def do_ls(self, arg):
        "List the current working directory on the server: ls"
        req = {"command": self.cmdp.cmd_lst}
        try:
            res = self.cmdp.send_command(req)
        except SiFT_CMD_Error as e:
            print("SiFT_CMD_Error: " + e.err_msg)
            return
        if res["result_1"] == self.cmdp.res_failure:
            print("Remote_Error: " + res["result_2"])
        else:
            print(res["result_2"] if res["result_2"] else "[empty]")

    def do_cd(self, arg):
        "Change working directory on the server: cd <dirname>"
        self._simple(self.cmdp.cmd_chd, arg)

    def do_mkd(self, arg):
        "Create a directory on the server: mkd <dirname>"
        self._simple(self.cmdp.cmd_mkd, arg)

    def do_del(self, arg):
        "Delete a file or empty directory on the server: del <name>"
        self._simple(self.cmdp.cmd_del, arg)

    def do_upl(self, arg):
        "Upload a local file to the server: upl <filepath>"
        filepath = arg.split(" ")[0]
        if not os.path.isfile(filepath):
            print(f"Local_Error: {filepath} does not exist or is not a file")
            return
        hash_fn = SHA256.new()
        file_size = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                file_size += len(chunk)
                hash_fn.update(chunk)
        req = {
            "command": self.cmdp.cmd_upl,
            "param_1": os.path.split(filepath)[1],
            "param_2": file_size,
            "param_3": hash_fn.digest(),
        }
        try:
            res = self.cmdp.send_command(req)
        except SiFT_CMD_Error as e:
            print("SiFT_CMD_Error: " + e.err_msg)
            return
        if res["result_1"] == self.cmdp.res_reject:
            print("Remote_Error: " + res["result_2"])
            return
        print("Starting upload...")
        try:
            SiFT_UPL(self.mtp).handle_upload_client(filepath)
        except SiFT_UPL_Error as e:
            print("Remote_Error: " + e.err_msg)
        else:
            print("Completed (server confirmed matching hash).")

    def do_dnl(self, arg):
        "Download a file from the server: dnl <filename>"
        req = {"command": self.cmdp.cmd_dnl, "param_1": arg.split(" ")[0]}
        try:
            res = self.cmdp.send_command(req)
        except SiFT_CMD_Error as e:
            print("SiFT_CMD_Error: " + e.err_msg)
            return
        if res["result_1"] == self.cmdp.res_reject:
            print("Remote_Error: " + res["result_2"])
            return
        print(f"File size: {res['result_2']}")
        print(f"File hash: {res['result_3'].hex()}")
        yn = ""
        while yn.lower() not in ("y", "yes", "n", "no"):
            yn = input("Do you want to proceed? (y/n) ")
        dnlp = SiFT_DNL(self.mtp)
        if yn.lower() in ("y", "yes"):
            print("Starting download...")
            try:
                got_hash = dnlp.handle_download_client(req["param_1"])
            except SiFT_DNL_Error as e:
                print("Remote_Error: " + e.err_msg)
                return
            # Integrity check: the downloaded bytes must match the advertised hash.
            if got_hash != res["result_3"]:
                print("Integrity_Error: downloaded file hash does NOT match advertised hash!")
            else:
                print("Completed (hash verified).")
        else:
            print("Canceling download...")
            try:
                dnlp.cancel_download_client()
            except SiFT_DNL_Error as e:
                print("Remote_Error: " + e.err_msg)

    def do_bye(self, arg):
        "Close the connection and exit: bye"
        print("Closing connection with server...")
        self.sckt.close()
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="SiFT secure file transfer client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5150)
    parser.add_argument("--public-key", default=os.path.join(HERE, "keys", "public_key.pem"))
    args = parser.parse_args()

    with open(args.public_key, "rb") as f:
        pubkey = RSA.import_key(f.read())
    fpr = SHA256.new(pubkey.export_key(format="DER")).hexdigest()

    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.connect((args.host, args.port))
    except OSError:
        print("Network_Error: cannot open connection to the server")
        sys.exit(1)
    print(f"Connected to {args.host}:{args.port}")
    print(f"Server public-key fingerprint (SHA-256): {fpr}")

    mtp = SiFT_MTP(sckt, role="client", server_pubkey=pubkey)
    loginp = SiFT_LOGIN(mtp)

    username = input("   Username: ")
    password = getpass.getpass("   Password: ")
    try:
        loginp.handle_login_client(username, password)
    except SiFT_LOGIN_Error as e:
        print("SiFT_LOGIN_Error: " + e.err_msg)
        sys.exit(1)

    cmdp = SiFT_CMD(mtp)
    SiFTShell(cmdp, mtp, sckt).cmdloop()


if __name__ == "__main__":
    main()
