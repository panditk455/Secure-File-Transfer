"""SiFT Download Protocol -- streams a file from the server in fragments.

The client sends a ``ready`` (or ``cancel``) request; on ``ready`` the server
streams the file in 1024-byte fragments, the last one carrying a distinct type.
The client computes a SHA-256 over what it receives so the caller can compare it
to the hash advertised in the download command response.
"""

from __future__ import annotations

from Crypto.Hash import SHA256

from .siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_DNL_Error(Exception):
    def __init__(self, err_msg: str) -> None:
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_DNL:
    def __init__(self, mtp: SiFT_MTP) -> None:
        self.size_fragment = 1024
        self.coding = "utf-8"
        self.ready = "ready"
        self.cancel = "cancel"
        self.mtp = mtp

    # -- client --------------------------------------------------------------

    def cancel_download_client(self) -> None:
        try:
            self.mtp.send_msg(self.mtp.type_dnload_req, self.cancel.encode(self.coding))
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error("Unable to send download request (cancel) --> " + e.err_msg)

    def handle_download_client(self, filepath: str) -> bytes:
        try:
            self.mtp.send_msg(self.mtp.type_dnload_req, self.ready.encode(self.coding))
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error("Unable to send download request (ready) --> " + e.err_msg)

        hash_fn = SHA256.new()
        with open(filepath, "wb") as f:
            download_complete = False
            while not download_complete:
                try:
                    msg_type, msg_payload = self.mtp.receive_msg()
                except SiFT_MTP_Error as e:
                    raise SiFT_DNL_Error("Unable to receive download response --> " + e.err_msg)
                if msg_type not in (self.mtp.type_dnload_res_0, self.mtp.type_dnload_res_1):
                    raise SiFT_DNL_Error("Download response expected, but received something else")
                if msg_type == self.mtp.type_dnload_res_1:
                    download_complete = True
                hash_fn.update(msg_payload)
                f.write(msg_payload)
        return hash_fn.digest()

    # -- server --------------------------------------------------------------

    def handle_download_server(self, filepath: str) -> None:
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error("Unable to receive download request --> " + e.err_msg)

        if msg_type != self.mtp.type_dnload_req:
            raise SiFT_DNL_Error("Download request expected, but received something else")

        if msg_payload.decode(self.coding) != self.ready:
            return  # client cancelled

        with open(filepath, "rb") as f:
            byte_count = self.size_fragment
            while byte_count == self.size_fragment:
                fragment = f.read(self.size_fragment)
                byte_count = len(fragment)
                msg_type = (self.mtp.type_dnload_res_0 if byte_count == self.size_fragment
                            else self.mtp.type_dnload_res_1)
                try:
                    self.mtp.send_msg(msg_type, fragment)
                except SiFT_MTP_Error as e:
                    raise SiFT_DNL_Error("Unable to download file fragment --> " + e.err_msg)
