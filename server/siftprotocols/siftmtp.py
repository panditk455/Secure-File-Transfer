import socket
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives.hashes import SHA256
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from os import urandom

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
    def __init__(self, peer_socket):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.msg_types = (self.type_login_req, self.type_login_res, 
                          self.type_command_req, self.type_command_res,
                          self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                          self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.tk = None
        self.final_transfer_key = None
        self.send_sequence_num = 0
        self.received_sequence_num = 0


    def set_final_session_key(self, key):
        self.final_transfer_key = key
        
	# parses a message header and returns a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):
        parsed_msg_hdr, i = {}, 0
        # Parse the protocol version (2 bytes)
        parsed_msg_hdr['ver'], i = msg_hdr[i:i+2], i+2
        # Parse the message type (2 bytes)
        parsed_msg_hdr['typ'], i = msg_hdr[i:i+2], i+2
        # Parse the message length (2 bytes)
        parsed_msg_hdr['len'], i = msg_hdr[i:i+2], i+2
        # Parse the sequence number (2 bytes)
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i+2], i+2
        # Parse the random value (6 bytes)
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+6], i+6
        # Parse the reserved field (2 bytes)
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i+2], i+2
        return parsed_msg_hdr



	# receives n bytes from the peer socket
    def receive_bytes(self, n):
        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk: 
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        print("bytes that were received by receive_bytes method")
        print(bytes_received.hex())
        return bytes_received



    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
            print("MESSAGE HEADER HERE")
            print(msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr: 
            raise SiFT_MTP_Error('Incomplete message header received')
        
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)  #####MESSAGE HEADER STUFF IS HERE

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
            print("length of the received message is:    " + str(len(msg_body)))
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
        

        ##### Start receiving the message 
        ##Check the sequence, makes sure the one received is one greater than the previous one
        received = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
        print(self.send_sequence_num)
        if received <= self.received_sequence_num:
            raise SiFT_MTP_Error('Message sequence number is too old')

        self.received_sequence_num = received

        # verify the mac and decrypts the encrypted payload with AES in GCM 
        if parsed_msg_hdr['typ'] == self.type_login_req:
            etk = msg_body[-256:]  # Extract the etk
            print("length of the etk is:    " + str(len(etk)))
            msg_body = msg_body[:-256]

            # with open("private_key.pem", "rb") as key_file:
            #     private_key = serialization.load_pem_private_key(key_file.read(), password=None)

            # tk = private_key.decrypt(
            #     etk,
            #     padding.OAEP(
            #         mgf=padding.MGF1(algorithm=SHA256()),
            #         algorithm=SHA256(),
            #         label=None
            #     )
            # )
            # self.tk = tk
            # print(f"Decrypted Temporary Key (tk): {tk.hex()}")

            with open("private_key.pem", "rb") as key_file:
                private_key = RSA.import_key(key_file.read())
            cipher_rsa = PKCS1_OAEP.new(private_key)
            tk = cipher_rsa.decrypt(etk)
            print(f"Decrypted Temporary Key (tk): {tk.hex()}")
            self.tk = tk
            
            # Time to decrypt message
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            msg_mac = msg_body[-12:] ## Extract the mac
            msg_body = msg_body[:-12]
            print(f"Nonce (SQN + RND): {nonce.hex()}")
            if len(nonce) != 8:
                raise ValueError("Nonce must be 8 bytes long for AES-GCM.")
            
            GCM = AES.new(tk, AES.MODE_GCM, nonce = nonce, mac_len = 12)
            GCM.update(msg_hdr)
            try:
                # Decrypt the payload and verify the MAC 
                decrypted_payload = GCM.decrypt_and_verify(msg_body, msg_mac)
            except Exception as e:
                print(f"Decryption failed or MAC verification failed: {str(e)}")
            print("DECRYPTION WORKED !!!!!")
                
        else:
            cur_key = self.final_transfer_key
            # Time to decrypt message
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            print(f"Nonce (SQN + RND): {nonce.hex()}")
            if len(nonce) != 8:
                raise ValueError("Nonce must be 8 bytes long for AES-GCM.")
            msg_mac = msg_body[-12:] ## Extract the mac
            msg_body = msg_body[:-12]
            print(f"Nonce (SQN + RND): {nonce.hex()}")
            if len(nonce) != 8:
                raise ValueError("Nonce must be 8 bytes long for AES-GCM.")
            
            GCM = AES.new(cur_key, AES.MODE_GCM, nonce = nonce, mac_len = 12)
            GCM.update(msg_hdr)
            try:
                # Decrypt the payload and verify the MAC 
                decrypted_payload = GCM.decrypt_and_verify(msg_body, msg_mac)
            except Exception as e:
                print(f"Decryption failed or MAC verification failed: {str(e)}")
            print("DECRYPTION WORKED !!!!!")
    
            

        # DEBUG 
        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_body)) + '): ')
            print(msg_body.hex())
            print('------------------------------------------')
            print("decrypted message payload:")
            print(decrypted_payload.hex())
        # DEBUG 

        if parsed_msg_hdr['typ'] == self.type_login_req:
            if len(msg_body) != msg_len - self.size_msg_hdr - len(msg_mac) - len(etk): 
                print(msg_len - self.size_msg_hdr)
                print(len(msg_body))
                raise SiFT_MTP_Error('Incomplete message body received')
        else:
            if len(msg_body) != msg_len - self.size_msg_hdr - len(msg_mac): 
                print(msg_len - self.size_msg_hdr)
                print(len(msg_body))
                raise SiFT_MTP_Error('Incomplete message body received')
        
        #self.send_sequence_num = self.send_sequence_num + 1


        print('------------------------------------------')
        print("I guess the decrypt was successfull???? ")
        print('------------------------------------------')
        return parsed_msg_hdr['typ'], decrypted_payload


    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            print(bytes_to_send.hex())
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')



        # builds and sends message of a given type using the provided payload
    # builds and sends message of a given type using the provided payload
    def send_msg(self, msg_type, msg_payload):
        payload_length = len(msg_payload)
        authtag_length = 12  # Authentication tag length
        header_length = self.size_msg_hdr 
        print("this is the current sqn: " + str(self.send_sequence_num))
        
        if msg_type == self.type_login_req:
            msg_length = header_length + payload_length + authtag_length + 256 # this accounts for the etk
        else:
            msg_length = header_length + payload_length + authtag_length ## have to include tk length if its a login request

        # Step 1: Build the Header
        header_version_field = self.msg_hdr_ver  # Protocol version
        header_length_field = msg_length.to_bytes(2, byteorder='big')  # Total message length
        header_sqn_field = (self.send_sequence_num + 1).to_bytes(2, byteorder='big')  # Sequence number
        self.send_sequence_num += 1
        header_rnd_field = urandom(6)  # 6-byte random value
        header_reserved_field = b'\x00\x00'  # Reserved field

        header = (header_version_field + msg_type + header_length_field +
                header_sqn_field + header_rnd_field + header_reserved_field)

        # Debugging Header Construction
        if self.DEBUG:
            print(f"Header Version Field (Protocol version): {header_version_field.hex()}")
            print(f"Header Length Field (Total message length): {header_length_field.hex()}")
            print(f"Header Sequence Number Field (Incremented sequence number): {header_sqn_field.hex()}")
            print(f"Header Random Field (6-byte random value): {header_rnd_field.hex()}")
            print(f"Header Reserved Field (Reserved for future use): {header_reserved_field.hex()}")
            print(f"Constructed Header: {header.hex()}")

        # Step 2: Handle Message Type
        if msg_type == self.type_login_req:
            print(f"Message Type: LOGIN REQUEST ({msg_type})")
            self.tk = urandom(32)  # Generate temporary key
            key = self.tk
            # Time to encrypt the payload
            nonce = header_sqn_field + header_rnd_field  # SQN|RND as the nonce
            AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
            AE.update(header)  # Authenticated encryption includes the header
            encrypted_payload, mac = AE.encrypt_and_digest(msg_payload)

            # Debugging encryption process
            if self.DEBUG:
                print(f"Encrypted Payload: {encrypted_payload.hex()}")
                print(f"Using Temporary Key (tk): {key.hex()}")

            # Encrypt the temporary key and append it to the payload
            # with open("public_key.pem", "rb") as key_file:
            #     public_key = serialization.load_pem_public_key(key_file.read())
            with open("public_key.pem", "rb") as key_file:
                public_key = RSA.import_key(key_file.read())
            
            # encrypted_key = public_key.encrypt(
            #     self.tk,
            #     padding.OAEP(
            #         mgf=padding.MGF1(algorithm=SHA256()),
            #         algorithm=SHA256(),
            #         label=None
            #     )
            # )
            # full_message = header + encrypted_payload + mac + encrypted_key
            symmetric_key = self.tk

            cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
            encrypted_key = cipher_rsa.encrypt(symmetric_key)
            
            full_message = header + encrypted_payload + mac + encrypted_key
        
        ###############
        elif msg_type == self.type_login_res:
            print(f"Message Type: LOGIN RESPONSE ({msg_type})")
            key = self.tk
            print("this is the key being used: " + key.hex())
            # Time to encrypt the payload
            nonce = header_sqn_field + header_rnd_field  # SQN|RND as the nonce
            AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
            AE.update(header)  # Authenticated encryption includes the header
            encrypted_payload, mac = AE.encrypt_and_digest(msg_payload)

            # Debugging encryption process
            if self.DEBUG:
                print(f"Encrypted Payload: {encrypted_payload.hex()}")
                print(f"Using Temporary Key (tk): {key.hex()}")
            full_message = header + encrypted_payload + mac

        else: 
            print(f"Message Type: OTHER ({msg_type})")
            key = self.final_transfer_key  # Use final transfer key for non-login messages
            # Time to encrypt the payload
            nonce = header_sqn_field + header_rnd_field  # SQN|RND as the nonce
            AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
            AE.update(header)  # Authenticated encryption includes the header
            encrypted_payload, mac = AE.encrypt_and_digest(msg_payload)

            

            # Debugging encryption process
            if self.DEBUG:
                print(f"Encrypted Payload: {encrypted_payload.hex()}")
                print(f"Using Final Transfer Key (tk): {key.hex()}")

            full_message = header + encrypted_payload + mac

       

        print("This is the full message:")
        print(full_message.hex())
        print("Length of the message" + str(len(full_message)))

        # Debugging message construction
        if self.DEBUG:
            print('MTP message to send (' + str(msg_length) + '):')
            print('HDR (' + str(len(header)) + '): ' + header.hex())
            print('BDY (' + str(len(encrypted_payload)) + '): ' + encrypted_payload.hex())
            print('MAC (' + str(len(mac)) + "):")
            print(msg_payload.hex())
            print('------------------------------------------')

        # Step 3: Send the message
        try:
            self.send_bytes(full_message)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

 






 













 






