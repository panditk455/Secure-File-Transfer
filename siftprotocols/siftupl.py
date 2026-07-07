"""SiFT Upload Protocol -- streams a file to the server in fragments.

The file is sent in 1024-byte fragments; the last fragment uses a distinct
message type so the receiver knows the transfer is complete. Both ends compute
a SHA-256 over the stream and the server echoes its hash back so the client can
confirm the upload arrived intact.
"""

from __future__ import annotations

from Crypto.Hash import SHA256

from .siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_UPL_Error(Exception):
    def __init__(self, err_msg: str) -> None:
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_UPL:
    def __init__(self, mtp: SiFT_MTP) -> None:
        self.delimiter = "\n"
        self.coding = "utf-8"
        self.size_fragment = 1024
        self.mtp = mtp

    def build_upload_res(self, s: dict) -> bytes:
        return (s["file_hash"].hex() + self.delimiter + str(s["file_size"])).encode(self.coding)

    def parse_upload_res(self, upl_res: bytes) -> dict:
        f = upl_res.decode(self.coding).split(self.delimiter)
        return {"file_hash": bytes.fromhex(f[0]), "file_size": int(f[1])}

    # -- client --------------------------------------------------------------

    def handle_upload_client(self, filepath: str) -> None:
        hash_fn = SHA256.new()
        with open(filepath, "rb") as f:
            byte_count = self.size_fragment
            while byte_count == self.size_fragment:
                fragment = f.read(self.size_fragment)
                byte_count = len(fragment)
                hash_fn.update(fragment)
                msg_type = (self.mtp.type_upload_req_0 if byte_count == self.size_fragment
                            else self.mtp.type_upload_req_1)
                try:
                    self.mtp.send_msg(msg_type, fragment)
                except SiFT_MTP_Error as e:
                    raise SiFT_UPL_Error("Unable to upload file fragment --> " + e.err_msg)
        file_hash = hash_fn.digest()

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_UPL_Error("Unable to receive upload response --> " + e.err_msg)

        if msg_type != self.mtp.type_upload_res:
            raise SiFT_UPL_Error("Upload response expected, but received something else")

        try:
            upl_res = self.parse_upload_res(msg_payload)
        except (ValueError, IndexError):
            raise SiFT_UPL_Error("Parsing upload response failed")

        if upl_res["file_hash"] != file_hash:
            raise SiFT_UPL_Error("Hash verification of uploaded file failed")

    # -- server --------------------------------------------------------------

    def handle_upload_server(self, filepath: str) -> None:
        hash_fn = SHA256.new()
        file_size = 0
        with open(filepath, "wb") as f:
            upload_complete = False
            while not upload_complete:
                try:
                    msg_type, msg_payload = self.mtp.receive_msg()
                except SiFT_MTP_Error as e:
                    raise SiFT_UPL_Error("Unable to receive upload request --> " + e.err_msg)
                if msg_type not in (self.mtp.type_upload_req_0, self.mtp.type_upload_req_1):
                    raise SiFT_UPL_Error("Upload request expected, but received something else")
                if msg_type == self.mtp.type_upload_req_1:
                    upload_complete = True
                file_size += len(msg_payload)
                hash_fn.update(msg_payload)
                f.write(msg_payload)

        msg_payload = self.build_upload_res({"file_hash": hash_fn.digest(), "file_size": file_size})
        try:
            self.mtp.send_msg(self.mtp.type_upload_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_UPL_Error("Unable to send upload response --> " + e.err_msg)
