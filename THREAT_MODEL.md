# SiFT v1.0 — STRIDE Threat Model

**System:** Hardened Python implementation of the SiFT v1.0 secure file-transfer protocol
**Repository:** [github.com/panditk455/Secure-File-Transfer](https://github.com/panditk455/Secure-File-Transfer) (branch `main`)
**Author:** Kritika Pandit
**Last reviewed:** 2026-07-06

This document models the security of the implementation as it actually exists in
`siftprotocols/` (`siftmtp.py`, `siftlogin.py`, `siftcmd.py`, `siftupl.py`,
`siftdnl.py`, `monitoring.py`) and the `server/` and `client/` entry points. Every
control cited below maps to a specific code path; every residual risk is one I can
point to in the source. The goal is not to claim the system is unbreakable — it is
to be precise about *what* it defends, *how*, and *where the edges are*.

---

## 1. Scope and assets

The protocol lets an authenticated user run file operations (`pwd, ls, cd, mkd,
del, upl, dnl`) inside a per-user directory on a remote server, over an untrusted
TCP network. The assets I care about, in rough priority order:

| Asset | Why it matters | Primary owner |
|---|---|---|
| **User credentials** | Passwords authenticate every session; a leak is a full account takeover. | `server/users.txt`, in transit inside login_req |
| **Server RSA private key** | Root of session-key establishment. Compromise breaks *all* sessions (see forward-secrecy note). | `server/keys/private_key.pem` (mode 600, git-ignored) |
| **File contents & integrity** | The actual payload the protocol exists to move; must arrive unread and unmodified. | Server filesystem + wire |
| **Session confidentiality & integrity** | Command/response and file bytes must be secret and tamper-evident on the wire. | AES-256-GCM session keys `k_c2s` / `k_s2c` |
| **Per-user directory boundary** | A user must not read, write, or traverse outside their own root. | `siftcmd.py` path checks |
| **Availability** | The server should keep serving legitimate clients under load / abuse. | `server/server.py`, `LoginGuard` |
| **Audit trail** | Detection and post-incident reconstruction. | `monitoring.py` event log |

**Out of scope:** the security of the host OS, the Python runtime and
`pycryptodome` itself, physical access to either machine, and the human process of
comparing the trust-on-first-use (TOFU) fingerprint. These are assumed-trusted or
assumed-correct; where that assumption is load-bearing I say so.

---

## 2. Trust boundaries and data flow

There are two trust boundaries that matter. **Boundary A** separates the trusted
client process (and the human at it) from the untrusted network. **Boundary B**
separates the trusted server process from both the network *and* its own
semi-trusted filesystem — the server does not trust filenames that arrive over the
wire, and it does not trust that a resolved path stays where the name implied.

```
        TRUST BOUNDARY A                                     TRUST BOUNDARY B
    (client host | network)                            (network | server | filesystem)
              ┃                                                    ┃
┌─────────────────────────┐   ┌────────────────────┐   ┌───────────────────────────┐   ┌───────────────────┐
│    CLIENT PROCESS        │   │  UNTRUSTED NETWORK │   │      SERVER PROCESS        │   │  SERVER FILESYSTEM │
│    (TRUSTED)             │   │  (Dolev–Yao:       │   │      (TRUSTED)             │   │  (SEMI-TRUSTED)    │
│                          │   │   read/modify/     │   │                            │   │                    │
│  • RSA public key        │   │   drop/replay/     │   │  • RSA private key (0600)  │   │  users.txt         │
│    (pinned, TOFU)        │   │   inject)          │   │  • users.txt → PBKDF2      │   │   (pwd hashes)     │
│  • session keys          │─ login_req ─▶ etk + │──▶│  • LoginGuard (shared)     │──▶│  per-user root/    │
│    k_c2s / k_s2c         │   │   AES-GCM ct + MAC │   │  • SecurityMonitor         │   │   ├ alice/         │
│  • cmd.Cmd shell         │◀─ login_res ─  AES-GCM│◀──│  • SiFT_CMD confinement    │◀──│   ├ bob/           │
│                          │   │   ct + MAC          │   │    (check_fdname+realpath) │   │   └ charlie/       │
│  verifies request_hash,  │   │                    │   │  • per-connection thread   │   │                    │
│  file SHA-256            │   │  ATTACKER SEES:    │   │                            │   │  realpath must stay │
│                          │   │   header (cleartext│   │  fail-closed AEAD, strict  │   │  under user root    │
│                          │   │   ver/typ/len/sqn),│   │  sequence numbers          │   │                    │
│                          │   │   ciphertext size, │   │                            │   │                    │
│                          │   │   message timing   │   │                            │   │                    │
└─────────────────────────┘   └────────────────────┘   └───────────────────────────┘   └───────────────────┘
```

**Data-flow summary.** The client pins the server's public key (prints its SHA-256
DER fingerprint on connect; the human compares it to the one `generate_keys.py`
emitted — TOFU). It generates a fresh 32-byte temporary key `tk`, RSA-OAEP-wraps it
to the server's RSA-2048 public key (`etk`, 256 bytes), and sends `login_req`
encrypted under `tk`. The server unwraps `tk`, authenticates the user, and both
sides derive two directional AES-256 keys via HKDF. From then on, every message is
`header ‖ AES-256-GCM ciphertext ‖ 12-byte tag`, with the 16-byte header
authenticated as associated data. File bytes are streamed in 1024-byte fragments
with an end-to-end SHA-256 check.

**Note on the header:** ver/typ/len/sqn/rnd are transmitted *in the clear* (they are
GCM associated data, integrity-protected but not encrypted). The attacker therefore
learns message types, sizes, and ordering — this is the metadata-leakage tradeoff
(§5).

---

## 3. STRIDE analysis

### S — Spoofing (identity)

| Threat | Control(s) in this codebase | Residual risk |
|---|---|---|
| Attacker impersonates a **user** (logs in as alice without her password). | Password auth via **PBKDF2-HMAC-SHA256**, per-user 16-byte salt, per-user iteration count (100,000 in the demo store); server compares against the stored hash only (`check_password`, `siftlogin.py`). Passwords never stored or compared in cleartext. Online guessing is throttled by `LoginGuard` (5 failures → 60 s per-user lockout, shared across connections). | Weak/guessable passwords still succeed; the demo passwords are intentionally trivial. Offline cracking is possible *if* `users.txt` leaks (§4). |
| Attacker impersonates the **server** (MITM presents a rogue public key). | Client prints the server public-key **SHA-256 fingerprint** and pins it TOFU; the RSA-OAEP key transport means only the holder of the real private key can unwrap `tk`, so a rogue server cannot complete the handshake or produce a valid `login_res` echoing `request_hash`. | Server authentication is **trust-on-first-use** and **manual** — the client does not persist or auto-compare the fingerprint; a user who ignores a first-connection MITM accepts the wrong key. No PKI/cert chain. |
| Replayed `login_req` to masquerade as a prior session. | Two independent checks in `handle_login_server`: a `LoginGuard` **replay cache** keyed on SHA-256 of the login payload (2 s window) and a **±2 s timestamp window** (`validate_timestamp`). The payload also carries 16 random bytes so genuine logins are unique. | An attacker with a >2 s-stale capture is rejected by the timestamp window; a <2 s replay is caught by the cache. The two windows are deliberately matched. |

### T — Tampering (with data)

| Threat | Control(s) | Residual risk |
|---|---|---|
| Modify ciphertext, header fields, or splice messages on the wire. | **AES-256-GCM AEAD**: any bit-flip in ciphertext, tag, *or* the 16-byte header (bound via `gcm.update(header)` as AAD) fails `decrypt_and_verify`. The implementation **fails closed** — a bad tag raises `SiFT_MTP_Error("MAC verification failed")`, emits a `mac_failure` alert, and never returns plaintext. The receive sequence number is committed *only after* successful verification. | None cryptographically material within a session (128-bit GCM tag truncated to 96 bits / 12 bytes — a deliberate, standard tradeoff; forgery probability ≈ 2⁻⁹⁶ per attempt). |
| Corrupt a file in transit (upload or download). | End-to-end **SHA-256 over the stream**. Upload: server echoes its computed hash, client aborts on mismatch (`handle_upload_client`). Download: client recomputes and `do_dnl` compares against the advertised hash, printing `Integrity_Error` on mismatch. | Integrity is verified but the hash comparison is *advisory* on download — the file is already written to disk before the check; a paranoid client should treat a mismatch as "delete and retry." |
| Reorder or reflect valid messages. | Per-direction, strictly increasing 2-byte **sequence numbers**; receiver rejects `sqn ≤ last_seen` (`sequence_violation` event). Directions use **different keys**, so a server→client message cannot be reflected as client→server. | Sequence space is 16 bits per direction; a session exceeding 65 535 messages in one direction would exhaust it. Fine for the intended use, worth noting. |

### R — Repudiation

| Threat | Control(s) | Residual risk |
|---|---|---|
| A user denies having performed an operation (login, delete, upload). | `SecurityMonitor` records structured JSON events (`login_success/failure`, `traversal_attempt`, `session_start/end`, …) with sequence numbers and timestamps to a ring buffer and an optional append-only JSONL log (`--log`). This is a server-side audit trail suitable for SOC ingestion. | **No cryptographic non-repudiation.** Messages are authenticated with a *symmetric* key both parties hold, and the log is server-attested — the server could in principle fabricate entries. Genuine non-repudiation would need per-user digital signatures, which SiFT v1.0 does not specify. Stated honestly: this is an *audit* trail, not *proof*. |

### I — Information disclosure

| Threat | Control(s) | Residual risk |
|---|---|---|
| Eavesdropper reads credentials or file contents on the wire. | Login payload is encrypted under `tk` (RSA-OAEP-wrapped); all post-login traffic is AES-256-GCM under HKDF-derived directional keys. Passwords are never sent or logged in cleartext. | Traffic *metadata* — message type, size, count, and timing — is visible because the header is cleartext AAD. File sizes and access patterns leak. |
| Secret leakage through logs / debug output. | The historic `DEBUG=True` path that printed `tk`, the derived session key, and decrypted payloads was **removed**; the optional tracer reduces key material to an 8-hex-char fingerprint (`_fingerprint`) unless explicitly built to reveal it. `monitoring.py` logs only truncated hashes/usernames. | The opt-in "reveal" tracer exists for the teaching demo; it must never be enabled in a real deployment. |
| Offline recovery of passwords from a stolen `users.txt`. | Stored as PBKDF2-HMAC-SHA256 with per-user salt and 100 k iterations — no plaintext, salted against rainbow tables, iteration count raises per-guess cost. | A flat file is a weaker store than an HSM-backed DB; 100 k iterations is reasonable but not memory-hard (Argon2/scrypt would resist GPU cracking better). Weak demo passwords fall quickly to a dictionary. |
| Username enumeration via login behaviour. | Uniform failure message ("unknown user or bad password") for both bad user and bad password. | **Timing side channel:** an unknown username short-circuits before PBKDF2 runs, so unknown-user responses are measurably faster than known-user-bad-password ones. This is a real, honest residual risk; a constant-time path (run PBKDF2 against a dummy salt for unknown users) would close it. |

### D — Denial of service

| Threat | Control(s) | Residual risk |
|---|---|---|
| Online password brute force. | `LoginGuard` per-user lockout (5 failures → 60 s), shared across all connections so an attacker cannot reset it by reconnecting. | Lockout is *per username*, so it is also a lever to lock a legitimate user out (a targeted DoS). Accepted tradeoff for a demo; production would add per-IP and CAPTCHA-style backpressure. |
| Oversized-message / giant-allocation attack. | The header length field is **2 bytes**, capping any single message at 65 535 bytes; `receive_msg` rejects lengths below the header size. There is no unbounded read. | The cap is structural, not configurable. |
| Malicious authenticated client fills the disk. | Upload command checks the *advertised* file size against the 64 KiB limit (`filesize_limit = 2**16`) before accepting. | **The streaming loop (`handle_upload_server`) does not re-enforce the limit per fragment** — a client that advertises a small size but keeps sending `upload_req_0` fragments can write past the limit. This is a genuine residual DoS I would fix by counting bytes written and aborting past the cap. Contained to authenticated users and their own directory, but real. |
| Connection / thread exhaustion. | Each connection runs on its own daemon thread; PBKDF2 cost is only paid for *known* usernames and is capped by lockout. | No cap on concurrent connections/threads beyond the OS backlog (`listen(5)`); an attacker opening many sockets can exhaust server threads/memory. A connection pool or per-IP rate limit is the mitigation. |

### E — Elevation of privilege

| Threat | Control(s) | Residual risk |
|---|---|---|
| Path traversal — escape the per-user root (`../../etc/passwd`, absolute paths, symlinks). | **Two independent defences.** (1) `check_fdname` allowlist rejects empty names, any leading `.` (blocks `..`), and any char outside `[A-Za-z0-9-_.]` (blocks `/`). (2) `_resolve` performs **realpath containment**: the resolved absolute path must equal the user root or start with `user_root + os.sep`, else the operation is refused. `realpath` also collapses symlinks, so a symlink pointing outside the root fails containment. Any rejection emits `traversal_attempt` → a `path_traversal` alert. | Confinement is *application-level*, not an OS chroot/sandbox — the server process still runs with the invoking user's privileges, so a defect elsewhere (or an RCE) would not be contained by these checks. No privilege separation between the network-facing loop and filesystem access. |
| Authenticated user reaches another user's files. | Each session is pinned to `users[user]["rootdir"]` from `users.txt`; all paths are built under that root. No command lets a user reference another user's root. | Depends on `users.txt` root assignments being correct and disjoint; a misconfigured overlapping root would break isolation. |
| Cross-session ciphertext replay to gain state. | Session keys are freshly derived per login (fresh `tk`, fresh randoms), so ciphertext from an old session cannot be decrypted or replayed into a new one. | None material; keys are ephemeral per session. |

---

## 4. Adversary model

I evaluate against a standard **Dolev–Yao** network attacker plus a few concrete
specializations. For each: what they *can* and *cannot* do here, and why.

**Passive eavesdropper (read-only wire access).**
*Can:* observe every byte on the wire, including the cleartext header — so message
types, sizes, counts, and timing. Learn *that* alice uploaded a ~40 KB file at
14:02.
*Cannot:* read credentials or file contents. The login payload is RSA-OAEP-wrapped +
AES-GCM; all later traffic is AES-256-GCM under HKDF keys. Without the server
private key or a session key, ciphertext is opaque.
*Why:* confidentiality rests on AEAD with keys the eavesdropper never sees.

**Active MITM (full Dolev–Yao: modify, drop, inject, reorder).**
*Can:* tamper with any byte, but every tamper is *detected* — GCM authenticates the
ciphertext, tag, and header (AAD), and the receiver fails closed. Can drop the
connection (a liveness attack, not a confidentiality/integrity break). Can attempt to
impersonate the server.
*Cannot:* forge a valid message (≈2⁻⁹⁶ per attempt), silently alter a header field,
or impersonate the server *provided the human verified the pinned fingerprint on
first connect*. A rogue server cannot unwrap `tk` (no private key) and so cannot
produce a `login_res` that echoes the client's `request_hash`.
*Why:* AEAD + header-as-AAD + RSA-OAEP key transport + TOFU pinning. **The load-bearing
assumption is the human comparing the fingerprint once.**

**Replay attacker.**
*Can:* capture and re-send prior messages.
*Cannot:* replay a `login_req` (2 s request-hash cache **and** ±2 s timestamp window),
replay within a session (strictly increasing per-direction sequence numbers), or
replay across sessions (fresh keys per login).
*Why:* layered anti-replay — a short-window cache for the fast path and a timestamp
bound for anything stale, plus monotonic sequence numbers under session-unique keys.

**Offline password cracker (has stolen `users.txt`).**
*Can:* mount an offline dictionary/brute-force attack against the PBKDF2 hashes;
weak passwords (like the demo ones) fall quickly.
*Cannot:* recover strong passwords cheaply — per-user salts defeat precomputation and
100 k iterations impose per-guess cost; and importantly, the online lockout is
irrelevant here (offline), so password *strength* is the only defence left.
*Why:* salted, iterated KDF. Honest limit: PBKDF2 is not memory-hard, so a GPU/ASIC
adversary gets good throughput; Argon2id would be the upgrade.

**Malicious authenticated user attempting traversal / abuse.**
*Can:* run the seven commands inside their own root; attempt `..`, crafted names,
symlinks.
*Cannot:* escape their root — `check_fdname` blocks the obvious vectors and `realpath`
containment blocks anything that slips past, including symlink escapes; both raise a
`path_traversal` alert. They cannot reach another user's directory.
*Can (residual):* over-fill their own directory by lying about upload size (§3-D), and
lock out another named user by triggering the failure threshold (§3-D).
*Why:* defence-in-depth on paths is strong; resource-abuse controls are the weaker
area and I call that out rather than paper over it.

**Denial-of-service adversary (unauthenticated).**
*Can:* open many connections to exhaust server threads (no connection cap beyond
`listen(5)`), or force PBKDF2 work — but only against *known* usernames, and lockout
caps that to 5 attempts / 60 s / user.
*Cannot:* trigger unbounded memory allocation (2-byte length cap) or force PBKDF2 work
against unknown usernames (short-circuit).
*Why:* the structural message-size cap and the KDF short-circuit blunt the cheap DoS
vectors; connection-count DoS is the acknowledged gap.

---

## 5. Residual risks and accepted tradeoffs

Stated plainly, because an interviewer should trust that I know where the edges are:

- **No forward secrecy.** Session keys ride on RSA key transport (the client's `tk`
  is encrypted *to* the server's long-term public key), not an (EC)DHE exchange.
  Consequence: an attacker who records ciphertext today and later compromises the
  server private key can decrypt every recorded past session. An ephemeral ECDHE
  handshake would give per-session forward secrecy; the tradeoff is handshake
  complexity and an extra round trip. This is the single most important limitation.

- **Server authentication is TOFU, and manual.** The client prints the public-key
  fingerprint but does not store or auto-compare it; trust rests on a human checking
  it once. There is no PKI, no certificate chain, no revocation. Right-sized for a
  teaching/demo protocol; a production system would pin persistently or use certs.

- **Metadata is not hidden.** The header is cleartext AAD, so message type, size,
  count, and timing leak to any observer. Length-hiding padding and cover traffic
  are out of scope for v1.0.

- **Flat-file user store.** `users.txt` (`username:pwdhash:icount:salt:rootdir`) is
  simple and auditable but is not an access-controlled, backed-up, HSM-fronted
  database. If it leaks, offline cracking begins.

- **PBKDF2, not a memory-hard KDF.** 100 k iterations is defensible but GPU-friendly;
  Argon2id/scrypt would raise the cost of offline cracking.

- **Demo passwords are intentionally weak** (alice/aaa, etc.) so the project runs out
  of the box. They are not a statement about the protocol's strength — but they *are*
  the reason the offline-cracker adversary succeeds quickly against this dataset.

- **Upload size limit is advisory during streaming**, and there is **no connection
  cap** — the two DoS gaps in §3-D. Both are fixable with a few lines (a running
  byte counter; a semaphore on concurrent handlers) and are the first things I would
  harden next.

- **Non-constant-time hash comparison** in `check_password` (`==` on bytes) and the
  **username-enumeration timing** side channel. Low practical severity, but both are
  worth naming and cheap to fix (constant-time compare; dummy PBKDF2 for unknown
  users).

- **The 12-byte (96-bit) GCM tag** is a deliberate size/security tradeoff, not a
  defect — it follows the SiFT v1.0 wire format and leaves forgery probability
  negligible.

None of these are hidden in the code; they are the honest boundary of a v1.0
protocol implemented carefully.

---

## 6. How detection complements prevention

Prevention fails silently; detection is how you *find out*. The `monitoring.py`
layer is deliberately decoupled from the crypto hot path — turning it off can only
reduce visibility, never weaken the protocol — and it turns the STRIDE story from
"we block X" into "we block X *and we would know if someone tried*."

The protocol layers emit structured events at exactly the points where an attack
manifests, and `SecurityMonitor` runs a few explainable threshold rules over them:

- **`brute_force_login`** — ≥5 failed logins for one username within 60 s. This is the
  visible signature of the online-guessing adversary that `LoginGuard`'s lockout is
  *preventing*: the lockout stops the attack, the alert tells the SOC it happened.
- **`tampering_suspected`** — ≥3 `mac_failure` events within 30 s. A single bad tag is
  noise; a burst is the signature of an active MITM probing the AEAD. Prevention
  (fail-closed GCM) already dropped the messages; the alert surfaces the *intent*.
- **`path_traversal`** — any rejected traversal attempt. `check_fdname` + realpath
  containment *prevent* the escape; the alert flags the authenticated user who tried,
  which is precisely the insider signal you want.

Every event and alert carries a sequence number and timestamp and can be streamed as
JSONL to a file (`--log`) for ingestion, giving the repudiation-resistant audit trail
of §3-R. The design point I would make in an interview: **the controls that prevent
each STRIDE threat also emit the telemetry that detects attempts against it**, so the
blue-team view and the red-team view are built from the same events rather than
bolted on afterward.
