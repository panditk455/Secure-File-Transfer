import sys, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random
from Crypto.Util.Padding import unpad

# Utility Functions
def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        return RSA.import_key(f.read())

def save_keypair(keypair, privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter the passphrase for the private key: ')
    with open(privkeyfile, 'rb') as f:
        return RSA.import_key(f.read(), passphrase=passphrase)

# Key Pair Generation
def generate_keys(pubkeyfile, privkeyfile):
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey(), pubkeyfile)
    save_keypair(keypair, privkeyfile)
    print('Key pair generated and saved.')

# Encryption
def encrypt_message(pubkeyfile, plaintext_file, output_file, privkeyfile=None, sign=False):
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    with open(plaintext_file, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
    symkey = Random.get_random_bytes(32)
    AEScipher = AES.new(symkey, AES.MODE_CBC)
    iv = AEScipher.iv
    ciphertext = AEScipher.encrypt(padded_plaintext)
    encsymkey = RSAcipher.encrypt(symkey)

    signature = b''
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = PKCS1_PSS.new(keypair)
        hashfn = SHA256.new(encsymkey + iv + ciphertext)
        signature = signer.sign(hashfn)

    with open(output_file, 'wb') as f:
        f.write(b'--- ENCRYPTED AES KEY ---\n')
        f.write(b64encode(encsymkey) + b'\n')
        f.write(b'--- IV FOR CBC MODE ---\n')
        f.write(b64encode(iv) + b'\n')
        f.write(b'--- CIPHERTEXT ---\n')
        f.write(b64encode(ciphertext) + b'\n')
        if sign:
            f.write(b'--- SIGNATURE ---\n')
            f.write(b64encode(signature) + b'\n')
    print('Encryption complete.')

# Decryption
def decrypt_message(privkeyfile, input_file, output_file, pubkeyfile=None, sign=False, passphrase=None):
    # Read the encrypted file contents
    print("from rsa")
    with open(input_file, 'rb') as f:
        lines = f.readlines()

    encsymkey = b64decode(lines[1].strip())
    iv = b64decode(lines[3].strip())
    ciphertext = b64decode(lines[5].strip())
    signature = b64decode(lines[7].strip()) if sign else b''

    # Signature verification if enabled
    if sign:
        pubkey = load_publickey(pubkeyfile)
        verifier = PKCS1_PSS.new(pubkey)
        hashfn = SHA256.new(encsymkey + iv + ciphertext)
        if not verifier.verify(hashfn, signature):
            print('Signature verification failed.')
            sys.exit(1)

    # Load the private key, with optional passphrase
    with open(privkeyfile, 'rb') as f:
        key_data = f.read()
        keypair = RSA.import_key(key_data, passphrase=passphrase)

    # Decrypt the symmetric key using RSA
    RSAcipher = PKCS1_OAEP.new(keypair)
    symkey = RSAcipher.decrypt(encsymkey)

    # Decrypt the ciphertext using AES
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)
    padded_plaintext = AEScipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size, style='pkcs7')

    # Write the decrypted plaintext to the output file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print('Decryption complete.')


if __name__ == '__main__':
    operation = input('Enter operation (kpg, enc, dec): ').strip()
    if operation == 'kpg':
        generate_keys('public.pem', 'private.pem')
    elif operation == 'enc':
        encrypt_message('test_pubkey.pem', 'test_plaintext1.txt', 'encrypted.txt', 'test_keypair.pem', sign=False)
    elif operation == 'dec':
        decrypt_message('test_keypair.pem', 'encrypted.txt', 'decrypted.txt', 'test_pubkey.pem', sign=False, passphrase="crysys")
    else:
        print('Invalid operation.')
