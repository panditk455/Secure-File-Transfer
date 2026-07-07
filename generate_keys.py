#!/usr/bin/env python3
"""Generate the RSA-2048 key pair used for SiFT session-key transport.

The server keeps the private key; the client is shipped only the public key
(out of band, in a real deployment). This script writes both and prints the
public-key fingerprint the client pins on first connect.

    python generate_keys.py                 # default paths, unencrypted private key
    python generate_keys.py --passphrase    # prompt for a passphrase to protect the key

Keys are git-ignored -- never commit a private key.
"""

from __future__ import annotations

import argparse
import getpass
import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

DEFAULT_PRIVKEY = os.path.join("server", "keys", "private_key.pem")
DEFAULT_PUBKEY = os.path.join("client", "keys", "public_key.pem")


def fingerprint(pubkey: RSA.RsaKey) -> str:
    der = pubkey.export_key(format="DER")
    return SHA256.new(der).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a SiFT RSA-2048 key pair")
    parser.add_argument("--private", default=DEFAULT_PRIVKEY, help="path for the private key")
    parser.add_argument("--public", default=DEFAULT_PUBKEY, help="path for the public key")
    parser.add_argument("--bits", type=int, default=2048, help="RSA key size (default 2048)")
    parser.add_argument("--passphrase", action="store_true",
                        help="prompt for a passphrase to encrypt the private key at rest")
    args = parser.parse_args()

    print(f"Generating a new {args.bits}-bit RSA key pair...")
    keypair = RSA.generate(args.bits)

    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Passphrase to protect the private key: ")

    for path in (args.private, args.public):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    with open(args.private, "wb") as f:
        f.write(keypair.export_key(format="PEM", passphrase=passphrase))
    os.chmod(args.private, 0o600)

    with open(args.public, "wb") as f:
        f.write(keypair.publickey().export_key(format="PEM"))

    print(f"  private key -> {args.private} (mode 600)")
    print(f"  public  key -> {args.public}")
    print(f"  public-key fingerprint (SHA-256): {fingerprint(keypair.publickey())}")
    print("Done. The private key is git-ignored; distribute only the public key to clients.")


if __name__ == "__main__":
    main()
