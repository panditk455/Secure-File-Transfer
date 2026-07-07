#!/usr/bin/env python3
"""SiFT server -- authenticates clients and serves per-user file operations.

Each connection is handled on its own thread: log the client in, then loop on
command requests. A shared ``LoginGuard`` enforces replay/brute-force limits
across all connections, and a shared ``SecurityMonitor`` records security events
(and raises alerts) that the web demo's dashboard can display.

    python server.py --host 127.0.0.1 --port 5150
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

from Crypto.PublicKey import RSA

# Make the repo-root ``siftprotocols`` package importable without installation.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siftprotocols import monitoring  # noqa: E402
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error  # noqa: E402
from siftprotocols.siftlogin import LoginGuard, SiFT_LOGIN, SiFT_LOGIN_Error  # noqa: E402
from siftprotocols.siftmtp import SiFT_MTP  # noqa: E402
from siftprotocols.siftupl import SiFT_UPL_Error  # noqa: E402
from siftprotocols.siftdnl import SiFT_DNL_Error  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


class Server:
    def __init__(self, host: str, port: int, privkey_path: str, users_path: str,
                 rootdir: str, monitor: monitoring.SecurityMonitor):
        self.host = host
        self.port = port
        self.server_rootdir = rootdir
        self.users_path = users_path
        self.monitor = monitor
        self.guard = LoginGuard(monitor=monitor)

        with open(privkey_path, "rb") as f:
            self.privkey = RSA.import_key(f.read())

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        print(f"SiFT server listening on {host}:{port}")

    def load_users(self) -> dict:
        users = {}
        with open(self.users_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                fields = line.split(":")
                users[fields[0]] = {
                    "pwdhash": bytes.fromhex(fields[1]),
                    "icount": int(fields[2]),
                    "salt": bytes.fromhex(fields[3]),
                    "rootdir": fields[4],
                }
        return users

    def accept_connections(self) -> None:
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()

    def handle_client(self, client_socket: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        self.monitor.record(monitoring.EVT_SESSION_START, peer=peer)
        mtp = SiFT_MTP(client_socket, role="server", server_privkey=self.privkey,
                       monitor=self.monitor, peer_name=peer)
        try:
            users = self.load_users()
            loginp = SiFT_LOGIN(mtp, guard=self.guard)
            loginp.set_server_users(users)
            try:
                user, _, _ = loginp.handle_login_server()
            except SiFT_LOGIN_Error as e:
                print(f"[{peer}] login failed: {e.err_msg}")
                return

            cmdp = SiFT_CMD(mtp)
            cmdp.set_server_rootdir(self.server_rootdir)
            cmdp.set_user_rootdir(users[user]["rootdir"])
            while True:
                cmdp.receive_command()
        except (SiFT_CMD_Error, SiFT_UPL_Error, SiFT_DNL_Error) as e:
            print(f"[{peer}] session ended: {e.err_msg}")
        finally:
            self.monitor.record(monitoring.EVT_SESSION_END, peer=peer)
            client_socket.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SiFT secure file transfer server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5150)
    parser.add_argument("--private-key", default=os.path.join(HERE, "keys", "private_key.pem"))
    parser.add_argument("--users", default=os.path.join(HERE, "users.txt"))
    parser.add_argument("--rootdir", default=os.path.join(HERE, "users") + os.sep)
    parser.add_argument("--log", default=None, help="write security events as JSON lines to this file")
    args = parser.parse_args()

    monitor = monitoring.SecurityMonitor(logfile=args.log)
    server = Server(args.host, args.port, args.private_key, args.users, args.rootdir, monitor)
    try:
        server.accept_connections()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
