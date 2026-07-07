#!/usr/bin/env python3
"""Attack: exploit AES-GCM nonce reuse -- and show why directional keys prevent it.

This is the weakness I found in my own protocol. The original design used ONE
session key for both directions, each with its own sequence counter starting at
the same value. So the client's message #1 and the server's message #1 shared the
same key and the same sequence number; nonce uniqueness rested entirely on the
6 random bytes. If those ever collided, two messages would be encrypted with the
same (key, nonce) -- catastrophic for a stream cipher like GCM's CTR core: the
keystreams are identical, so XORing the two ciphertexts cancels the keystream and
leaks the XOR of the two plaintexts.

The fix: derive SEPARATE keys per direction (k_c2s, k_s2c) via HKDF. Now even an
identical (sequence, random) pair across the two directions uses different keys,
so the keystreams differ and nothing leaks.
"""

import os

from Crypto.Cipher import AES

from _harness import banner, blocked, leaked, note


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def run() -> bool:
    banner("AES-GCM nonce reuse: vulnerable single-key vs fixed directional keys")

    nonce = os.urandom(8)                       # the SAME nonce in both directions
    p_client = b"MOVE $1000 TO ACCOUNT 0001 NOW!!"   # 31 bytes
    p_server = b"ACK: balance is now 0000042 USD"    # 31 bytes (equal length)

    # --- Vulnerable design: one key, reused nonce across the two directions ---
    shared = os.urandom(32)
    c1 = AES.new(shared, AES.MODE_GCM, nonce=nonce).encrypt(p_client)
    c2 = AES.new(shared, AES.MODE_GCM, nonce=nonce).encrypt(p_server)
    recovered = _xor(_xor(c1, c2), p_client)    # attacker knows/guesses p_client
    note("single shared key, same nonce both directions:")
    if recovered == p_server:
        leaked("keystream cancelled -> recovered the OTHER plaintext: "
               f"{recovered!r}")
    else:
        note("(unexpected) plaintext not recovered")

    # --- Fixed design: directional keys from HKDF ---
    k_c2s, k_s2c = os.urandom(32), os.urandom(32)   # what HKDF gives us: two keys
    d1 = AES.new(k_c2s, AES.MODE_GCM, nonce=nonce).encrypt(p_client)
    d2 = AES.new(k_s2c, AES.MODE_GCM, nonce=nonce).encrypt(p_server)
    recovered2 = _xor(_xor(d1, d2), p_client)
    note("directional keys (k_c2s != k_s2c), even with the same nonce:")
    if recovered2 == p_server:
        leaked("plaintext still recovered -- fix ineffective!")
        return False
    blocked("keystreams differ -> XOR reveals nothing usable: "
            f"{recovered2[:16].hex()}...")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
