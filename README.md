# SiFT v1.0 — Secure File Transfer

A hardened, from-scratch implementation of the **SiFT (Simple File Transfer) v1.0** secure protocol in Python. This repository implements the **encrypted** v1.0 profile end to end: an **AES-256-GCM** authenticated-encryption transport, an **RSA-OAEP + HKDF** login handshake that derives *directional* session keys, strict sequence-number **replay defence**, a **red-team attack harness**, structured **security monitoring with threshold detection**, a **test suite**, and **CI**. It is built as much for the blue team as the red team — every protocol event is observable, and the design decisions (and their residual risks) are documented rather than hand-waved.

[![CI](https://img.shields.io/github/actions/workflow/status/panditk455/Secure-File-Transfer/ci.yml?branch=main&label=CI)](https://github.com/panditk455/Secure-File-Transfer/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#license)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

---

## Live demo

**▶ [Interactive SiFT Protocol Explorer](https://panditk455.github.io/Secure-File-Transfer/)** — a byte-level walkthrough of the handshake and the AES-GCM message format, with a tamper toggle that shows the MAC failing closed. Every value is computed live in your browser with the Web Crypto API; no install required. Source: [`docs/index.html`](docs/index.html), served via GitHub Pages (Settings → Pages → Deploy from a branch → `main` → `/docs`).

For the full system, the **Flask demo in [`webdemo/`](webdemo/)** drives a *real* client/server session and streams each SiFT message on the wire — header fields, GCM ciphertext, MAC, and verification status — beside a live security dashboard that fires detection alerts as you attack the protocol:

```bash
pip install -r requirements.txt
python webdemo/app.py            # then open http://127.0.0.1:8000  (login alice / aaa)
```

---

## Security features

| Feature | Primitive / mechanism | Why it matters |
| --- | --- | --- |
| **AEAD transport** | AES-256-GCM; 8-byte nonce `sqn‖rnd`; 12-byte tag; the 16-byte header bound as AAD (`GCM.update(header)`) | Confidentiality *and* integrity in one pass. Any bit flipped in the ciphertext **or the header** fails tag verification. |
| **Key transport** | RSA-2048 with **OAEP(SHA-256)** wrapping a fresh 256-bit temporary key (`etk`, 256 bytes) | Bootstraps a symmetric session with no pre-shared secret. OAEP closes the door on textbook-RSA and padding-oracle attacks. |
| **Directional session keys** | **HKDF-SHA256** over `client_random‖server_random`, salted with the request hash, split by context labels `client-to-server` / `server-to-client` → two independent 32-byte keys | Each direction gets its own key, so a `(key, nonce)` pair can never repeat across directions — this is what eliminates the GCM nonce-reuse risk. |
| **Password storage** | **PBKDF2-HMAC-SHA256**, 100,000 iterations, 16-byte per-user salt, 32-byte derived key | Passwords are never stored or compared in the clear. Per-user salting defeats rainbow tables; the high iteration count slows offline cracking. |
| **Replay / reordering defence** | Per-direction, strictly increasing 2-byte sequence numbers; a frame with `sqn ≤ last_seen` is rejected, and the counter is committed **only after** authentication | A captured message cannot be replayed or reordered into the stream. |
| **File integrity** | Streaming **SHA-256** over each transfer; server echoes the hash on upload, client verifies received bytes against the advertised hash on download | End-to-end detection of truncation, corruption, or tampering of file contents. |
| **Path-traversal containment** | `check_fdname` allowlist (rejects empty names, leading `.`, and anything outside `[A-Za-z0-9-_.]`) **plus** an independent `realpath` containment check under the user root | Two layers confine every user to their own directory. Even a name that slipped the allowlist must still resolve inside the root, or the operation is refused and flagged. |
| **Fail-closed AEAD** | A failed `decrypt_and_verify` raises `SiFT_MTP_Error`, emits a `mac_failure` event, and returns **no** plaintext | Authenticated encryption must fail closed — unverified bytes never reach the application layer. |
| **Security monitoring + detection** | `SecurityMonitor` records structured JSONL events and runs threshold rules: brute-force login, MAC-failure spikes (suspected tampering), and path-traversal attempts | Turns raw protocol events into SOC-ingestible telemetry and alerts. Decoupled from the crypto path, so disabling it reduces visibility without weakening the protocol. |

---

## Architecture

```
  ┌─────────────────────────────┐                     ┌─────────────────────────────┐
  │           CLIENT            │                     │           SERVER            │
  │   client.py (cmd shell)     │                     │  server.py (thread/conn)    │
  │                             │                     │                             │
  │   SiFT_CMD   (file ops)     │                     │   SiFT_CMD   (file ops)     │
  │   SiFT_LOGIN (auth + keys)  │                     │   SiFT_LOGIN + LoginGuard   │
  │   SiFT_MTP   (AES-256-GCM)  │                     │   SiFT_MTP   (AES-256-GCM)  │
  └──────────────┬──────────────┘                     └──────────────┬──────────────┘
                 │                                                    │
                 │  (1) LOGIN HANDSHAKE                               │
                 │  login_req: hdr ‖ GCM_tk(ts,user,pwd,cRnd) ‖ MAC   │
                 │             ‖ etk = RSA-OAEP(tk)                    │  decrypt etk (RSA),
                 │ ─────────────────────────────────────────────────►│  PBKDF2 verify, replay
                 │                                                    │  cache + lockout checks
                 │  login_res: hdr ‖ GCM_tk(req_hash, sRnd) ‖ MAC     │
                 │ ◄─────────────────────────────────────────────────│
                 │   both sides: k_c2s, k_s2c = HKDF(cRnd‖sRnd)       │
                 │                                                    │
                 │  (2) SESSION — one key per direction               │
                 │  command / upload / download frames:               │
                 │  hdr(AAD) ‖ AES-256-GCM ‖ MAC(12)   [k_c2s] ──────►│
                 │ ◄────── [k_s2c]   hdr(AAD) ‖ AES-256-GCM ‖ MAC(12) │
                 │                                                    │
                 └──────────────────────────────────────────────┐    │
                        every server-side security event ────────┼────┘
                                                                 ▼
                                                   ┌─────────────────────────┐
                                                   │     SecurityMonitor     │
                                                   │  JSONL event log (ring  │
                                                   │  buffer + optional file)│
                                                   │  detection → alerts     │
                                                   └─────────────────────────┘
```

Every SiFT message is `header(16) ‖ AES-256-GCM ciphertext ‖ MAC(12)`; the login request additionally carries the 256-byte RSA-OAEP-wrapped temporary key. The header is authenticated as associated data but not encrypted. After login, the two directions use different keys, so the sequence number in the nonce guarantees a unique `(key, nonce)` pair per message.

---

## Repository layout

```
Secure-File-Transfer/
├── siftprotocols/            # shared protocol package — imported by everything below
│   ├── __init__.py
│   ├── siftmtp.py            # Message Transfer Protocol: AES-256-GCM AEAD transport, fail-closed
│   ├── siftlogin.py          # login handshake, PBKDF2 auth, HKDF directional keys, LoginGuard
│   ├── siftcmd.py            # command layer + path-traversal containment
│   ├── siftupl.py            # chunked upload  (1024-byte fragments, SHA-256)
│   ├── siftdnl.py            # chunked download (1024-byte fragments, SHA-256)
│   └── monitoring.py         # SecurityMonitor: structured events + threshold detection
├── server/
│   ├── server.py             # threaded server; shared LoginGuard + SecurityMonitor
│   ├── users.txt             # username:pbkdf2_hash:iters:salt:rootdir  (no plaintext passwords)
│   ├── users/                # per-user root directories (alice/ bob/ charlie/)
│   └── keys/                 # private_key.pem — git-ignored, generated locally
├── client/
│   ├── client.py             # cmd.Cmd shell; prints the pinned server-key fingerprint
│   └── keys/                 # public_key.pem — git-ignored
├── tests/                    # pytest + hypothesis: unit, property, and integration tests
├── attacks/                  # red-team harness: tamper / replay / traversal / downgrade / nonce-reuse
├── webdemo/                  # Flask app: live wire panel + security dashboard
├── docs/                     # index.html — the interactive site (served via GitHub Pages)
├── _specification/           # SiFT v1.0 protocol specification
├── THREAT_MODEL.md           # STRIDE threat model
├── SECURITY_ANALYSIS.md      # self-authored audit: 11-finding hardening report
├── generate_keys.py          # RSA-2048 keypair generator; prints the SHA-256 fingerprint
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Quick start

Requires Python 3.9+ and a single crypto dependency (`pycryptodome`). Run everything from the repository root.

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt      # or: pip install -e ".[dev,demo]"

# 3. Generate the RSA-2048 key pair (writes server/keys + client/keys)
python generate_keys.py              # prints the server public-key SHA-256 fingerprint
```

Then start the server and client in two terminals:

```bash
# Terminal 1 — server (defaults to 127.0.0.1:5150)
python server/server.py

# Terminal 2 — client
python client/client.py
```

`--host` and `--port` are configurable on both ends (the server also takes `--private-key`, `--users`, `--rootdir`, and `--log` for a JSONL security-event file). On connect, the client prints the **server public-key SHA-256 fingerprint** — compare it to the fingerprint `generate_keys.py` printed. SiFT trusts the server key on first use, so a mismatch is how you would catch a man-in-the-middle.

Log in with a demo account:

```
   Username: alice
   Password: aaa
```

Demo users are `alice/aaa`, `bob/bbb`, `charlie/ccc` — all stored as PBKDF2 hashes, never plaintext. The passwords are intentionally weak for demonstration only.

---

## Commands

Once logged in, the client presents a shell (`(sift)`); type `help` for the list.

| Command | Action |
| --- | --- |
| `pwd` | Print the current working directory on the server |
| `ls` | List the current server directory |
| `cd <dir>` | Change directory (`..` moves up; confined to your root) |
| `mkd <dir>` | Create a directory |
| `del <name>` | Delete a file or empty directory |
| `upl <path>` | Upload a local file (SHA-256 verified end to end) |
| `dnl <name>` | Download a file (received bytes verified against the advertised SHA-256) |
| `bye` | Close the connection and exit |

---

## Try to break it

The `attacks/` directory is a self-contained red-team harness. Each script mounts a specific active attack against a live session and shows the protocol's defensive response:

- **Tamper** — flip a byte in the ciphertext or the authenticated header; GCM tag verification fails closed, a `mac_failure` event fires, and a burst trips the `tampering_suspected` alert.
- **Replay** — capture and re-send a valid frame; the strictly-increasing sequence-number check rejects it, and a duplicated login request is caught by the request-hash replay cache.
- **Traversal** — request names such as `..`, `../etc/passwd`, or absolute paths; the `check_fdname` allowlist and `realpath` containment both refuse it and raise a `path_traversal` alert.
- **Downgrade** — send an unsupported version or unknown message type; the header is validated and the connection is rejected with a `protocol_error`.
- **Nonce-reuse** — demonstrates why single-key-both-directions was unsafe and shows that directional HKDF keys make a cross-direction `(key, nonce)` collision impossible.

## Run the tests

```bash
pip install -e ".[dev]"     # pytest, hypothesis, bandit, pip-audit
pytest                      # unit, property (hypothesis), and integration tests
bandit -r siftprotocols server client   # static security scan
pip-audit                   # dependency vulnerability audit
```

---

## Security posture

Full write-ups live in [`THREAT_MODEL.md`](THREAT_MODEL.md), [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md), and the protocol spec at [`_specification/SiFT v1.0 specification.md`](_specification/SiFT%20v1.0%20specification.md).

**Notable hardening fixes** (documented in the security analysis, and good interview material):

- MAC-verification failure used to print-and-continue, leaving the decrypted payload unbound — effectively **failing open**. It now **fails closed** with a clean rejection.
- A single symmetric key was used in **both** directions with only a 6-byte random nonce (a nonce-reuse risk); replaced with **directional HKDF keys**.
- The replay cache did `add → sleep(2) → remove`, which made it useless *and* blocked the login thread; replaced with a real windowed cache and per-user brute-force lockout.
- A debug mode printed the temporary key, derived session keys, passwords, and decrypted payloads; removed in favour of an opt-in, secret-redacting tracer.
- Downloaded-file hashes were computed but never checked; now verified client-side.

**Residual risks (stated honestly):**

- **No forward secrecy.** Session keys ride on RSA key transport, not (EC)DHE. Compromise of the server private key retroactively exposes any recorded past sessions. An ephemeral (EC)DHE handshake would fix this; the tradeoff is added protocol complexity.
- **Server authentication is trust-on-first-use.** The client pins the server public-key fingerprint on first connect — there is no PKI or certificate chain, so the first connection must be trusted out of band.
- **Metadata is not hidden.** Message sizes and timing are observable. The 6 random nonce bytes are kept as defence-in-depth on top of directional-key separation.
- **Demo-grade user store.** `users.txt` is a flat file, not a database, and the demo passwords are deliberately weak.

---

## Contributors

- Kritika Pandit
- Daniel Lumbu

## License

Released under the **MIT License**.
