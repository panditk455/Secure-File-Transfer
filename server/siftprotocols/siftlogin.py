import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
import binascii
import os


class SiFT_LOGIN_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_LOGIN:
    def __init__(self, mtp):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.timestamp_window = 2  # 2 seconds for timestamp validation
        self.recent_requests = set()  # To store hashes of recently processed requests
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None  # Dictionary of users: {username: {pwdhash, salt, icount}}

    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users
    
    def parse_login_req(self, login_req):
        # Define the expected field keys in the correct order
        field_keys = ["timestamp", "username", "password", "client_random"]
        
        # Decode the payload and split by the delimiter
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        
        # Ensure the payload has the expected number of fields
        if len(login_req_fields) != len(field_keys):
            raise SiFT_LOGIN_Error("Invalid login request format: unexpected number of fields")
        
        # Map the keys to their respective values
        login_req_struct = dict(zip(field_keys, login_req_fields))
        return login_req_struct

    # Utility: Generate 16-byte random value
    def generate_random(self):
        return os.urandom(16)
    
    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash'].hex() 
        login_res_str += self.delimiter + login_res_struct['server_random'].hex() 
        print(login_res_str.encode(self.coding))
        return login_res_str.encode(self.coding)

    # Utility: Validate timestamp
    def validate_timestamp(self, received_timestamp):
        current_time = int(time.time())  # Get current server time in seconds
        received_time = int(received_timestamp) // 1000000000  # Convert received timestamp from nanoseconds to seconds

        if self.DEBUG:
            print(f"DEBUG: Current server time: {current_time}")
            print(f"DEBUG: Received timestamp (converted to seconds): {received_time}")

        # Check if received timestamp is within the acceptable window
        if received_time < (current_time - self.timestamp_window) or received_time > (current_time + self.timestamp_window):
            raise SiFT_LOGIN_Error("Timestamp outside acceptable window")

    # Utility: Prevent duplicate requests
    def prevent_duplicate_request(self, request_hash):
        if request_hash in self.recent_requests:
            raise SiFT_LOGIN_Error("Duplicate request detected")
        # Maintain the record of recent requests for the acceptance window duration
        self.recent_requests.add(request_hash)
        # Remove the hash after the timestamp window duration
        time.sleep(self.timestamp_window)
        self.recent_requests.remove(request_hash)

    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):
        pwdhash = PBKDF2(
            pwd, 
            usr_struct['salt'], 
            len(usr_struct['pwdhash']), 
            count=usr_struct['icount'], 
            hmac_hash_module=SHA256
        )
        return pwdhash == usr_struct['pwdhash']

    # handles login process (to be used by the server)
    def handle_login_server(self):
        if not self.server_users:
            raise SiFT_LOGIN_Error("User database is required for handling login at server")

        # Receive login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to receive login request --> " + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print(f"Incoming payload ({len(msg_payload)}):")
            print(msg_payload[:max(512, len(msg_payload))].decode("utf-8"))
            print("------------------------------------------")

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error("Login request expected, but received something else")

        # Process login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # Prevent duplicate requests
        self.prevent_duplicate_request(request_hash)

        login_req_struct = self.parse_login_req(msg_payload)

        # Validate timestamp
        self.validate_timestamp(login_req_struct["timestamp"])

        # Check username and password
        if login_req_struct["username"] in self.server_users:
            user_data = self.server_users[login_req_struct["username"]]
            if not self.check_password(login_req_struct["password"], user_data):
                raise SiFT_LOGIN_Error("Password verification failed")
        else:
            raise SiFT_LOGIN_Error("Unknown user attempted to log in")

        # Generate server random
        server_random = self.generate_random()

        # Build login response
        login_res_struct = {
            "request_hash": request_hash,
            "server_random": server_random,
        }
        msg_payload = self.build_login_res(login_res_struct)
        print("checking...")
        print(login_res_struct['request_hash'])
        print(login_res_struct["server_random"])

        print("checking the message payload")
        print(msg_payload)

        # DEBUG
        if self.DEBUG:
            print(f"Outgoing payload ({len(msg_payload)}):")
            print(msg_payload[:max(512, len(msg_payload))].decode("utf-8"))
            print("------------------------------------------")

        # Send login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to send login response --> " + e.err_msg)

        # Derive final transfer key
        client_random = bytes.fromhex(login_req_struct["client_random"])
        final_key = HKDF(
            master=client_random + server_random,
            key_len=32,
            salt=request_hash,
            hashmod=SHA256,
        )

        # DEBUG
        if self.DEBUG:
            print(f"User {login_req_struct['username']} logged in successfully")
            print(f"Derived final transfer key: {final_key.hex()}")

        # Return username and final transfer key  
        return login_req_struct["username"], final_key


