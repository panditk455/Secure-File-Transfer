# SiFT v1.0 — Security Analysis & Hardening Report

**System:** SiFT v1.0 secure file-transfer protocol (Python / pycryptodome)
**Author:** Kritika Pandit · **Reviewed:** 2026-07-06
**Companion docs:** [THREAT_MODEL.md](THREAT_MODEL.md) · [SiFT v1.0 specification](_specification/SiFT%20v1.0%20specification.md)

This is a self-authored security review of my own project. I reviewed the original
implementation as an adversary would, wrote a runnable exploit harness
([`attacks/`](attacks/)) to *prove* each issue, fixed them, and left the harness and
[test suite](tests/) behind as living evidence that the fixes hold. The point of the
document is not to claim the result is unbreakable — it is to show *how I found the
problems, how I reasoned about severity, and where the remaining edges are.*

---

## 1. Methodology

1. **Manual code review** of the transport (`siftmtp.py`), login (`siftlogin.py`),
   and command (`siftcmd.py`) layers, focused on the cryptographic core: nonce
   management, MAC verification, key handling, error paths, and input parsing.
2. **Adversarial harness** — for every claimed defence I wrote an attack that tries
   to break it (`attacks/run_all.py`): bit-flip tampering, replay, protocol
   downgrade / header tampering, path traversal by an authenticated insider, and a
   concrete AES-GCM nonce-reuse exploit.
3. **Regression tests** — 33 `pytest` cases including AEAD known-answer/round-trip,
   fail-closed behaviour, sequence-number rejection, PBKDF2/HKDF, and
   property-based fuzzing of the parsers with Hypothesis.
4. **Automated scanning** in CI — Bandit (SAST), pip-audit (dependency CVEs), and
   gitleaks (secret scanning).

## 2. Findings summary

| # | Finding | Severity | CWE | Status |
|---|---------|----------|-----|--------|
| F-1 | RSA private key committed to version control | **Critical** | CWE-321 / CWE-540 | Fixed |
| F-2 | AES-GCM nonce reused across the two directions (single session key) | **High** | CWE-323 | Fixed |
| F-3 | AEAD failed **open** on bad MAC (print-and-continue → crash) | **High** | CWE-347 / CWE-390 | Fixed |
| F-4 | Secrets (temp key, session key, password, plaintext) logged to stdout | **High** | CWE-532 | Fixed |
| F-5 | Replay cache non-functional + blocking sleep in login path | **Medium** | CWE-294 / CWE-400 | Fixed |
| F-6 | No brute-force / rate-limit protection on login | **Medium** | CWE-307 | Fixed |
| F-7 | Downloaded-file hash computed but never verified | **Medium** | CWE-354 | Fixed |
| F-8 | Only one path-traversal defence (name allowlist), no containment backstop | **Medium** | CWE-22 | Fixed (defence-in-depth) |
| F-9 | Hardcoded server IP — the project would not run for anyone else | **Low** | CWE-1188 | Fixed |
| F-10 | `exec_upl` raised the wrong exception class | **Low** | CWE-397 | Fixed |
| F-11 | Two divergent half-copies of the protocol (dead/broken branches) | **Low** | CWE-1041 | Fixed |

---

## 3. Findings in detail

### F-1 · RSA private key committed to version control — *Critical*
**Observed.** `server/private_key.pem`, an unencrypted RSA-2048 private key, was
checked into the repository. Because SiFT establishes every session key by
RSA-wrapping a temporary key to this key, anyone with the repo could decrypt the
temporary key of any recorded session and, from there, the entire session.
**Fix.** Removed the key from the tree; added a `.gitignore` covering `*.pem` and
the `keys/` directories; moved key creation into `generate_keys.py` (writes the
private key `chmod 600`); added **gitleaks** secret scanning to CI so a future
committed secret fails the build. **Residual.** The key still exists in git
*history*; because it was a throwaway demo key the remediation is to rotate it and,
optionally, scrub history with `git filter-repo`. This is called out honestly rather
than hidden.

### F-2 · AES-GCM nonce reuse across directions — *High*
**Observed.** Client and server encrypted under **one** shared session key, each
with its own sequence counter starting at the same value and an 8-byte nonce of
`sqn(2) || rnd(6)`. So the client's message #1 and the server's message #1 used the
same key and the same 2-byte sequence prefix; uniqueness rested on 6 random bytes.
A nonce collision under one key is catastrophic for GCM (a CTR-mode stream): the
keystream repeats and `C1 ⊕ C2 = P1 ⊕ P2` leaks plaintext.
**Proof.** [`attacks/attack_nonce_reuse.py`](attacks/attack_nonce_reuse.py)
reconstructs the server's plaintext from two same-(key,nonce) ciphertexts.
**Fix.** Derive **two directional keys** via HKDF-SHA256 with distinct context
labels (`client-to-server`, `server-to-client`). The two directions now use
different keys, so even an identical `(sqn, rnd)` pair cannot produce a shared
`(key, nonce)`. The harness confirms the same XOR attack now recovers nothing.
This is the finding I'm proudest of — it's a real, subtle protocol bug I found and
fixed in my own design.

### F-3 · AEAD failed open on MAC verification failure — *High*
**Observed.** `decrypt_and_verify` was wrapped in `try/except` that merely printed
the error and continued. On tampering the tag check raises, so `decrypted_payload`
was left unbound and the code either crashed (`UnboundLocalError`) or, worse,
proceeded — the antithesis of authenticated encryption, which must **fail closed**.
**Fix.** A failed verification now raises `SiFT_MTP_Error("MAC verification
failed")`, emits a `mac_failure` security event, and never returns plaintext; the
receive sequence number is committed only *after* successful authentication.
**Proof.** [`attacks/attack_tamper.py`](attacks/attack_tamper.py) and
`tests/test_mtp.py::test_tampered_ciphertext_fails_closed`.

### F-4 · Sensitive data written to stdout — *High*
**Observed.** `DEBUG = True` throughout, printing the temporary key, the derived
session key, decrypted payloads, and — on login — the user's password.
**Fix.** Removed the debug prints; introduced an **opt-in, secret-redacting** trace
hook (`SiFT_MTP` `tracer`) that surfaces only header/ciphertext/MAC metadata and a
key *fingerprint*, never raw key material, unless explicitly asked. Default output
is silent. Verified by running the server/client with no secrets on stdout.

### F-5 · Broken replay cache + blocking sleep — *Medium*
**Observed.** The login replay cache did `add(hash)` → `time.sleep(2)` →
`remove(hash)`, so it both failed to remember requests and blocked the handler
thread for two seconds on every login (a self-inflicted DoS).
**Fix.** `LoginGuard` keeps `(request_hash → timestamp)` and prunes by the
acceptance window with no sleeping. `tests/test_login.py::test_replay_cache_rejects_duplicate`.

### F-6 · No brute-force protection — *Medium*
**Observed.** Unlimited password guesses per user.
**Fix.** `LoginGuard` enforces a per-user lockout (5 failures → 60 s), shared across
connections so opening new sockets doesn't reset it, and every failure raises a
`login_failure` event feeding the `brute_force_login` detection rule.

### F-7 · Download integrity never checked — *Medium*
**Observed.** The client computed the SHA-256 of a downloaded file but discarded it
(`# we could also check here...`), so a corrupted or substituted download went
unnoticed.
**Fix.** `client.py` now compares the received hash to the advertised hash and
raises an integrity error on mismatch. `tests/test_cmd.py::test_upload_download_roundtrip_with_hash`.

### F-8 · Single path-traversal defence — *Medium (defence-in-depth)*
**Observed.** Containment relied solely on the `check_fdname` allowlist. Sound, but
a single point of failure.
**Fix.** Added an independent `realpath`-containment check (`_resolve`): the
resolved absolute path must remain under the user's root or the operation is
refused, and the attempt is logged as `traversal_attempt` (→ `path_traversal`
alert). [`attacks/attack_traversal.py`](attacks/attack_traversal.py) exercises
`..`, absolute paths, and encoded separators.

### F-9 / F-10 / F-11 — *Low*
Hardcoded server IP `192.168.20.39` → configurable `--host/--port` (the project now
runs anywhere); `exec_upl` raised `SiFT_DNL_Error` → corrected to `SiFT_UPL_Error`;
two divergent, dead-branch-riddled copies of the protocol consolidated into one
shared, tested `siftprotocols/` package.

---

## 4. Verification

```
$ pytest -q
33 passed

$ python attacks/run_all.py
[DEFENCE HELD] Ciphertext tampering
[DEFENCE HELD] Message replay
[DEFENCE HELD] Protocol downgrade / header tampering
[DEFENCE HELD] Path traversal (authenticated user)
[DEFENCE HELD] Nonce reuse (single-key vs directional keys)
```

CI additionally runs Bandit (SAST), pip-audit (dependency CVEs), and gitleaks
(secret scanning) on every push.

## 5. Accepted residual risks

These are conscious tradeoffs, documented so they're decisions rather than
oversights (full treatment in [THREAT_MODEL.md](THREAT_MODEL.md)):

- **No forward secrecy.** Session keys ride on RSA key transport, not (EC)DHE, so
  compromise of the server private key retroactively exposes recorded sessions.
  Adding an ephemeral ECDHE exchange would close this at the cost of handshake
  complexity.
- **Trust-on-first-use server authentication** via a printed public-key
  fingerprint; there is no PKI/certificate chain.
- **Metadata** (message sizes, timing) is not concealed.
- **`users.txt`** is a flat file and the demo passwords are intentionally weak.
