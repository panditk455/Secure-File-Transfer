# SiFT v1.0 — Secure File Transfer Protocol Specification

**Status:** Normative. This document describes the protocol as *implemented* in this
repository (the shared `siftprotocols/` package), not an aspirational design. Every
byte layout, field, constant, and algorithm below is drawn directly from the source.
Where the reference code and this document disagree, the code is authoritative and the
document is a bug.

**Reference implementation:** [`github.com/panditk455/Secure-File-Transfer`](https://github.com/panditk455/Secure-File-Transfer) (branch `main`)
· Python 3 · single cryptographic dependency: [`pycryptodome`](https://pypi.org/project/pycryptodome/).

**Relationship to prior work.** SiFT v0.5 (the specification previously in this folder)
transmitted the login request and password in the clear and used a single symmetric key in
both directions. v1.0 is a hardened redesign: it is authenticated-encryption-only from the
first byte after the header, derives *independent per-direction* session keys, and fails
closed on any integrity failure. v1.0 is **not** wire-compatible with v0.5.

---

## 1. Overview

SiFT is a client–server protocol for authenticated, confidential file transfer over a
single TCP connection. A client logs in with a username and password; on success both
parties hold two fresh symmetric keys and the client may issue file-system commands
(`pwd`, `lst`, `chd`, `mkd`, `del`, `upl`, `dnl`) that operate inside a per-user root
directory on the server.

The protocol is layered:

| Layer | Module | Responsibility |
|---|---|---|
| **MTP** — Message Transfer Protocol | `siftmtp.py` | Framing, AEAD (AES-256-GCM), sequence numbers, RSA-OAEP key transport. Every higher layer sends and receives only through MTP. |
| **Login** sub-protocol | `siftlogin.py` | Password authentication (PBKDF2), replay/lockout defence, session-key establishment (HKDF). |
| **Command** sub-protocol | `siftcmd.py` | Serialises file-operation requests/responses; enforces path containment. |
| **Upload / Download** sub-protocols | `siftupl.py` / `siftdnl.py` | Fragmented file streaming with SHA-256 end-to-end integrity. |
| **Monitoring** (out-of-band) | `monitoring.py` | Structured security-event logging and threshold detection. Not on the crypto path. |

### 1.1 Security goals

- **Confidentiality.** After the header, all payload bytes are encrypted under AES-256-GCM. The header itself carries no secret material.
- **Integrity / authenticity of messages.** Every message carries a 96-bit GCM authentication tag computed over both the ciphertext *and* the 16-byte header (the header is bound as Additional Authenticated Data). A single altered bit anywhere in the header or ciphertext causes verification to fail.
- **Peer / user authentication.** The client authenticates the *server* by pinning its RSA public-key fingerprint (trust-on-first-use). The server authenticates the *user* with a salted, iterated password hash (PBKDF2-HMAC-SHA256).
- **Replay and reordering resistance.** Per-direction, strictly increasing sequence numbers reject stale or duplicated messages; the login exchange additionally has a timestamp window and a request-hash replay cache.
- **Online-guessing resistance.** A shared, server-wide per-user brute-force lockout throttles password guessing across connections.

### 1.2 Non-goals (stated honestly)

- **No forward secrecy.** Session keys are transported by wrapping a client-chosen key to the server's long-lived RSA key. If the server private key is ever compromised, an adversary who recorded past sessions can recover their session keys and decrypt them retroactively. A (EC)DHE handshake would fix this at the cost of added complexity; it was consciously not implemented.
- **Server authentication is trust-on-first-use (TOFU).** There is no PKI, certificate chain, or revocation. The client prints the server public-key SHA-256 fingerprint on connect and the operator is expected to compare it out of band. A first-connection man-in-the-middle who can substitute a public key is not detected.
- **No traffic-metadata protection.** Message lengths and timing are visible on the wire; the protocol does not pad or cover-traffic. An observer can distinguish, e.g., a `pwd` from a large upload.
- **Demo-grade credential store.** `users.txt` is a flat file, not a database, and the shipped demo passwords are deliberately weak. The password *hashing* is real; the password *policy* is not.

### 1.3 Cryptographic primitives

| Purpose | Primitive | Parameters |
|---|---|---|
| Authenticated encryption | AES-256-GCM | 256-bit key, 8-byte nonce, 12-byte (96-bit) tag |
| Session-key transport | RSA-OAEP | RSA-2048, OAEP with SHA-256 |
| Password verification | PBKDF2-HMAC-SHA256 | per-user 16-byte salt, 100 000 iterations, 32-byte output |
| Session-key derivation | HKDF-SHA256 | 32-byte output per direction (see §5.5) |
| Integrity hashing | SHA-256 | request hashes, file hashes, key fingerprints |

### 1.4 Notation

- `X(n)` denotes an `n`-byte field named `X`. All multi-byte integers are **big-endian** ("network byte order").
- `||` denotes concatenation. `LF` denotes the single byte `0x0A`. Text fields are UTF-8.
- Byte offsets are zero-based. Hex literals are written `0x…`.

---

## 2. The Message Transfer Protocol (MTP)

Every SiFT message is:

```
message = header(16) || ciphertext(v) || mac(12) [ || etk(256) ]
```

The `etk` trailer is present **only** on the `login_req` message. `ciphertext` has the same
length `v` as the plaintext payload (GCM is a stream cipher construction — no padding).

### 2.1 The 16-byte header

The header is transmitted in the clear but is authenticated (it is fed to GCM as AAD, so it
cannot be modified without breaking tag verification).

```
 offset  0      2      4      6      8                    14     16
         +------+------+------+------+---------------------+------+
         | ver  | typ  | len  | sqn  |        rnd          | rsv  |
         +------+------+------+------+---------------------+------+
           2 B    2 B    2 B    2 B          6 B             2 B
```

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 2 | `ver` | Protocol version. **Fixed `0x0100`** (major 1, minor 0). A receiver rejects any other value. |
| 2 | 2 | `typ` | Message type code (see §2.2). Unknown types are rejected. |
| 4 | 2 | `len` | **Total** message length in bytes, *including* the 16-byte header, the MAC, and (for `login_req`) the 256-byte `etk`. Big-endian; maximum 65535. A receiver rejects `len < 16`. |
| 6 | 2 | `sqn` | Message sequence number for this sender/direction, big-endian (see §3). First message is `1`. |
| 8 | 6 | `rnd` | 6 fresh random bytes, regenerated per message. |
| 14 | 2 | `rsv` | Reserved. **Fixed `0x0000`.** |

A useful identity: the 8-byte GCM nonce is exactly `header[6:14]` — the `sqn || rnd` slice
of the header (see §2.4).

### 2.2 Message types

| Code (hex) | Name | Direction | Sub-protocol |
|---|---|---|---|
| `0x0000` | `login_req` | client → server | Login |
| `0x0010` | `login_res` | server → client | Login |
| `0x0100` | `command_req` | client → server | Command |
| `0x0110` | `command_res` | server → client | Command |
| `0x0200` | `upload_req_0` | client → server | Upload (non-final fragment) |
| `0x0201` | `upload_req_1` | client → server | Upload (final fragment) |
| `0x0210` | `upload_res` | server → client | Upload (result + hash) |
| `0x0300` | `dnload_req` | client → server | Download (`ready` / `cancel`) |
| `0x0310` | `dnload_res_0` | server → client | Download (non-final fragment) |
| `0x0311` | `dnload_res_1` | server → client | Download (final fragment) |

### 2.3 On-wire message formats

There are exactly two frame formats.

**Format A — `login_req` only** (carries the RSA-wrapped temporary key at the tail):

```
+-----------+------------------------+---------+-----------------+
| header    | ciphertext             | mac     | etk             |
| 16 bytes  | len-16-12-256 bytes    | 12 B    | 256 bytes       |
+-----------+------------------------+---------+-----------------+
```

`etk` = `RSA-OAEP(server_pubkey, tk)`, a 256-byte RSA-2048 ciphertext. Note `etk` follows the
MAC; it is *not* covered by the GCM tag (its integrity comes from OAEP itself, and the payload
encrypted under the wrapped key `tk` is what the tag protects).

**Format B — every other message type:**

```
+-----------+------------------------+---------+
| header    | ciphertext             | mac     |
| 16 bytes  | len-16-12 bytes        | 12 B    |
+-----------+------------------------+---------+
```

### 2.4 AEAD construction

MTP uses **AES-256-GCM** for confidentiality and integrity in a single pass.

| Element | Value |
|---|---|
| Cipher | AES-256-GCM (`AES.MODE_GCM`) |
| Key | 32 bytes. Which key depends on message type (§2.6). |
| Nonce | `sqn(2) || rnd(6)` = **8 bytes**, taken from the outgoing header. |
| AAD | The entire 16-byte header (`gcm.update(header)`). |
| Tag (`mac`) | **12 bytes** (`mac_len = 12`). |
| Plaintext | The sub-protocol payload. |

Encryption: `ciphertext, mac = AES-GCM(key, nonce).update(header).encrypt_and_digest(payload)`.
Verification: `payload = AES-GCM(key, nonce).update(header).decrypt_and_verify(ciphertext, mac)`.

**Fail-closed rule (critical).** If `decrypt_and_verify` raises (tag mismatch, i.e. any
tampering or a wrong key), the receiver:

1. emits a `mac_failure` security event at severity **ALERT**,
2. raises `SiFT_MTP_Error("MAC verification failed")`, and
3. **never returns any plaintext** and **does not advance the receive sequence number**.

There is no code path that returns unauthenticated data. (This closes a defect in the original
implementation, where a MAC failure printed a warning and continued with an unbound
`decrypted_payload` — an effective fail-*open*.)

### 2.5 Receive algorithm and validation order

`receive_msg()` performs these steps in order; any failure raises `SiFT_MTP_Error` and aborts:

1. Read exactly 16 header bytes; parse fields.
2. Reject if `ver != 0x0100` → `protocol_error` (unsupported version).
3. Reject if `typ` is not a known type → `protocol_error` (unknown type).
4. Reject if `len < 16`.
5. Read the remaining `len - 16` body bytes.
6. **Sequence check (pre-decryption):** reject if `sqn <= received_sequence_num` → `sequence_violation`. (This cheaply drops replays/reorders before doing crypto work; the counter is only *committed* in step 10.)
7. If `typ == login_req` (server only): split off the trailing 256-byte `etk`, RSA-OAEP-decrypt it to recover `tk`; on failure → `protocol_error`. Use `key = tk`.
   Else if `typ == login_res`: use `key = tk`.
   Else: use `key = recv_key` (the installed directional receive key).
8. Reject if no key is available (out-of-order handshake), or if the body is shorter than the 12-byte MAC.
9. Split body into `ciphertext || mac`; build nonce = `sqn || rnd`; `decrypt_and_verify`. On failure apply the fail-closed rule (§2.4).
10. **Only now** set `received_sequence_num = sqn`.
11. Return `(typ, plaintext)`.

### 2.6 Which key encrypts which message

| Message type | Key used |
|---|---|
| `login_req` | `tk` — a fresh 32-byte key the client generates per session and RSA-wraps to the server. |
| `login_res` | `tk` — the same temporary key, before directional keys are installed. |
| all others | Directional key: sender uses `k_c2s` if client / `k_s2c` if server; receiver uses the opposite. |

---

## 3. Sequence numbers and nonce management

Each `SiFT_MTP` endpoint keeps two counters: `send_sequence_num` (its outgoing messages) and
`received_sequence_num` (the peer's incoming messages). Both start at `0`.

- **On send:** increment `send_sequence_num` first, then use it. Hence the first message a
  party sends has `sqn = 1`.
- **On receive:** the message is rejected unless `sqn > received_sequence_num`. After a message
  authenticates, `received_sequence_num` is set to that `sqn`. Strictly increasing ⇒ replays and
  reorders are refused.

**Why (key, nonce) reuse cannot happen.** GCM's one non-negotiable requirement is that a
(key, nonce) pair is never reused. SiFT guarantees this structurally:

- The temporary key `tk` encrypts exactly two messages: `login_req` (from the client) and
  `login_res` (from the server). The server sets `send_sequence_num = received_sequence_num`
  before replying, so `login_req` uses `sqn = 1` and `login_res` uses `sqn = 2` — **distinct
  nonces under `tk`** even though both directions momentarily share that key.
- After login, the two directions use **different keys** (`k_c2s`, `k_s2c`). Only the client
  ever encrypts with `k_c2s` and only the server ever encrypts with `k_s2c`, and each does so
  with its own strictly increasing `send_sequence_num`. Within one key the nonce's `sqn`
  component never repeats; across the two keys a shared `sqn` is harmless because the keys
  differ.
- The 6 random `rnd` bytes are retained as defence-in-depth on top of this separation, not as
  the primary guarantee.

This directional-key separation is the fix for the original protocol's single-shared-key
design, in which client→server and server→client messages could collide on a (key, nonce) pair.

---

## 4. Login sub-protocol (`siftlogin.py`)

The login exchange is a single request/response that simultaneously authenticates the user and
establishes the two session keys.

```
client                                                        server
  |  login_req  (typ 0x0000, sqn=1, under tk, + etk)            |
  |------------------------------------------------------------>|
  |                        [ decrypt tk, verify, authenticate ] |
  |  login_res  (typ 0x0010, sqn=2, under tk)                   |
  |<------------------------------------------------------------|
  | [ both sides derive k_c2s, k_s2c via HKDF; keys installed ] |
```

### 4.1 Temporary key generation and transport

The client generates `tk = 32 random bytes` per session, encrypts the login request payload
under `tk` with AES-256-GCM, and wraps `tk` with RSA-OAEP (SHA-256) to the server's RSA-2048
public key, yielding the 256-byte `etk` appended to the `login_req` frame (Format A, §2.3).
The server recovers `tk` by OAEP-decrypting `etk` with its private key.

### 4.2 `login_req` payload grammar

```abnf
login-req-payload = timestamp LF username LF password LF client-random

timestamp     = 1*DIGIT       ; str(time.time_ns()) — integer nanoseconds since the Unix epoch
username      = *no-LF        ; UTF-8
password      = *no-LF        ; UTF-8
client-random = 32HEXDIG      ; 16 random bytes, lowercase hex

LF    = %x0A
no-LF = %x00-09 / %x0B-10FFFF (UTF-8)
```

Exactly four `LF`-separated fields are required; any other count is a parse error.

### 4.3 Server-side processing order

On receiving `login_req` the server performs, in this order (any failure aborts the login):

1. `tk` is already recovered and the payload authenticated by MTP (§2.5).
2. Compute `request_hash = SHA-256(login_req_payload)` (32 bytes).
3. **Replay cache** (`LoginGuard.check_not_replay`): if `request_hash` was seen within the last
   **2 seconds**, reject as a probable replay (`replay_attempt`). Otherwise record it with the
   current time. Expired entries are pruned on each check.
4. Parse the four fields.
5. **Timestamp window** (`validate_timestamp`): reject unless `|now_ns − timestamp| ≤ 2×10⁹`
   ns (±2 seconds). A non-integer timestamp is a malformed-request error.
6. **Lockout check** (`assert_not_locked`): reject if the username is currently locked out
   (`rate_limited`).
7. **Password verification** (`check_password`): compute
   `PBKDF2-HMAC-SHA256(password, salt, dkLen=32, count=100000)` and compare in full to the
   stored `pwdhash`. Authentication succeeds iff the username exists **and** the hash matches.
8. On failure: record the failure (feeds the lockout counter), emit `login_failure`, and abort.
9. On success: clear the user's failure state, then build and send `login_res`.

### 4.4 `login_res` payload grammar and the sequence rule

```abnf
login-res-payload = request-hash LF server-random

request-hash  = 64HEXDIG     ; SHA-256 of the login_req payload, echoed back for binding
server-random = 32HEXDIG     ; 16 random bytes chosen by the server
```

Before sending, the server executes `send_sequence_num = received_sequence_num`. Since the
authenticated `login_req` set `received_sequence_num = 1`, and `send_msg` pre-increments, the
`login_res` goes out with `sqn = 2` — a nonce distinct from the request's under the shared `tk`
(see §3).

The client verifies that the echoed `request_hash` equals the hash of the request it sent; a
mismatch aborts the login. This binds the response to the specific request and confirms the
server actually decrypted `tk`.

### 4.5 Directional session-key derivation (HKDF)

Both parties derive the same two 32-byte keys from the two randoms, using HKDF-SHA256:

| HKDF parameter | Value |
|---|---|
| Input keying material (`master`) | `client_random(16) || server_random(16)` (32 bytes, raw) |
| Salt | `request_hash` (the 32-byte SHA-256 digest) |
| Hash | SHA-256 |
| Output length (`key_len`) | 32 bytes per key |
| Context / info (`k_c2s`) | `b"SiFT v1.0 client-to-server"` |
| Context / info (`k_s2c`) | `b"SiFT v1.0 server-to-client"` |

```
k_c2s = HKDF(ikm, 32, salt=request_hash, SHA256, context=b"SiFT v1.0 client-to-server")
k_s2c = HKDF(ikm, 32, salt=request_hash, SHA256, context=b"SiFT v1.0 server-to-client")
```

`k_c2s` protects client→server traffic; `k_s2c` protects server→client traffic. The distinct
context labels make the two keys cryptographically independent even though they share input
keying material and salt. After derivation each side installs the pair with
`set_session_keys(k_c2s, k_s2c)` and the temporary key `tk` is no longer used.

### 4.6 Online-guessing / replay defences (`LoginGuard`)

`LoginGuard` is a single, thread-safe object **shared across all connections**, so an attacker
cannot escape the limits by opening a fresh socket per attempt.

| Defence | Parameters | Behaviour |
|---|---|---|
| Request-hash replay cache | window 2 s | Duplicate `login_req` payload within the window is rejected. |
| Per-user brute-force lockout | 5 failures / 60 s → 60 s lockout | The 6th failed attempt inside a 60 s sliding window locks the account for 60 s. A success clears the counter. |

---

## 5. Command sub-protocol (`siftcmd.py`)

After login the client sends `command_req` messages and the server replies with `command_res`.
Each response echoes `request_hash = SHA-256(command_req_payload)`, which the client verifies
to bind the response to its request. Commands run relative to an in-memory current directory
that starts at the user root.

### 5.1 Commands

| Wire command | Client shell verb | Parameters |
|---|---|---|
| `pwd` | `pwd` | none |
| `lst` | `ls` | none |
| `chd` | `cd` | directory name (or `..`) |
| `mkd` | `mkd` | directory name |
| `del` | `del` | file or empty-directory name |
| `upl` | `upl` | filename, filesize, SHA-256 hash |
| `dnl` | `dnl` | filename |

(The shell additionally offers `bye`, which is local — it closes the socket and does not map to
a wire command.)

### 5.2 `command_req` payload grammar

```abnf
command-req  = simple-cmd / param-cmd / upload-cmd

simple-cmd   = "pwd" / "lst"
param-cmd    = ("chd" / "mkd" / "del" / "dnl") LF fdname
upload-cmd   = "upl" LF fdname LF filesize LF filehash

fdname       = 1*fdchar          ; and MUST NOT begin with "." (see §5.4)
fdchar       = ALPHA / DIGIT / "-" / "_" / "."
filesize     = 1*DIGIT           ; decimal byte count
filehash     = 64HEXDIG          ; client's SHA-256 of the file to upload
```

`chd` accepts the literal `..` as a special token meaning "parent" (handled in memory, §5.4);
`..` is otherwise rejected by the name allowlist.

### 5.3 `command_res` payload grammar

Every response begins with a common prefix, then a per-command tail:

```abnf
command-res  = command LF request-hash LF result-1 [ LF tail ]

request-hash = 64HEXDIG                    ; SHA-256 of the corresponding command_req payload
result-1     = "success" / "failure"       ; for pwd, lst, chd, mkd, del
             / "accept"  / "reject"        ; for upl, dnl
```

| Command | On success/accept, tail | On failure/reject, tail |
|---|---|---|
| `pwd` | `LF cwd` where `cwd = ["/".join(dirs)] "/"` (always ends in `/`; root is `/`) | — |
| `lst` | `LF base64(listing)` — the newline-joined directory listing, base64-encoded so its internal newlines don't collide with the field delimiter; hidden (`.`-prefixed) entries are omitted, directories get a trailing `/` | `LF error-message` |
| `chd` | (no tail) | `LF error-message` |
| `mkd` | (no tail) | `LF error-message` |
| `del` | (no tail) | `LF error-message` |
| `upl` | (no tail — `accept`) | `LF error-message` (`reject`) |
| `dnl` | `LF filesize LF filehash` (`accept`; server-computed size and SHA-256) | `LF error-message` (`reject`) |

### 5.4 Path-safety rules

User confinement is enforced by **two independent checks**; a name must pass both.

1. **Name allowlist (`check_fdname`).** Rejects a name that is empty, begins with `.` (which
   blocks `..` and hidden files), or contains any character outside `[A-Za-z0-9-_.]` (which
   blocks `/` and therefore any embedded path separator).
2. **Realpath containment (`_resolve`).** Independently, the candidate path
   `realpath(server_root / user_root / current_dir / name)` must equal the user root or begin
   with `user_root + os.sep`. If it escapes, the operation is refused. This is defence-in-depth:
   even a name that somehow passed the allowlist cannot resolve outside the user's tree
   (e.g. via a symlink).

`chd ..` is handled purely in memory by popping the current-directory list; it can never rise
above the user root (attempting to go up from the root returns a failure). Any rejected name
from a `chd`/`mkd`/`del`/`upl`/`dnl` emits a `traversal_attempt` event, which raises a
`path_traversal` alert (§7).

---

## 6. Upload sub-protocol (`siftupl.py`)

Upload is a three-phase exchange: a `command_req(upl, …)` that the server must `accept`, then a
fragment stream, then an `upload_res` carrying the server's hash for client verification.

```
client                                                        server
  | command_req  upl \n name \n size \n hash                    |
  |------------------------------------------------------------>|
  | command_res  upl \n <hash> \n accept   (or reject+reason)   |
  |<------------------------------------------------------------|
  | upload_req_0  (1024-byte fragment)      * zero or more      |
  |------------------------------------------------------------>|
  | upload_req_1  (final fragment, 0..1024 bytes)               |
  |------------------------------------------------------------>|
  | upload_res   <server_sha256_hex> \n <byte_count>            |
  |<------------------------------------------------------------|
```

**Acceptance.** The server rejects `upl` if the filename fails the path-safety checks (§5.4) or
if `filesize` exceeds the file-size limit (default `2**16` = 65536 bytes = 64 KiB).

**Fragmentation.** The file is read in 1024-byte fragments. Each full 1024-byte fragment is sent
as `upload_req_0`; the first short read (a fragment of length 0–1023, which occurs at end of
file — and is a 0-length fragment if the file size is an exact multiple of 1024) is sent as
`upload_req_1`, the terminal type that tells the server the stream is complete.

**Integrity.** Both ends run a SHA-256 over the byte stream. The server's `upload_res` reports
its computed hash and byte count:

```abnf
upload-res = filehash LF filesize
filehash   = 64HEXDIG      ; server's SHA-256 of the received bytes
filesize   = 1*DIGIT       ; received byte count
```

The client compares the server's hash to its own; a mismatch raises `SiFT_UPL_Error`
("Hash verification of uploaded file failed"). Because each fragment is an ordinary MTP message,
every fragment is independently AEAD-protected and sequence-checked; the SHA-256 comparison is
an additional end-to-end check on top of per-message integrity.

---

## 7. Download sub-protocol (`siftdnl.py`)

Download reuses the `command_req(dnl, …)` accept step (which returns the server-computed size
and hash, §5.3) and then streams fragments after an explicit client `ready`.

```
client                                                        server
  | command_req  dnl \n name                                    |
  |------------------------------------------------------------>|
  | command_res  dnl \n <hash> \n accept \n <size> \n <sha256>  |
  |<------------------------------------------------------------|
  | dnload_req   "ready"   (or "cancel")                        |
  |------------------------------------------------------------>|
  | dnload_res_0  (1024-byte fragment)      * zero or more      |
  |<------------------------------------------------------------|
  | dnload_res_1  (final fragment, 0..1024 bytes)               |
  |<------------------------------------------------------------|
```

**Request.** The `dnload_req` payload is the literal text `ready` or `cancel`. On `cancel` (or
any payload other than `ready`) the server returns without streaming.

**Fragmentation** is identical to upload: `dnload_res_0` for each full 1024-byte fragment,
`dnload_res_1` for the terminal (possibly empty) fragment.

**Integrity.** The client computes a SHA-256 over the received stream and compares it to the
hash advertised in the `command_res` (which the server computed by reading the file before
streaming). A mismatch is surfaced as an integrity error and the downloaded file is treated as
untrusted. (Verifying the downloaded hash closes a gap in the original implementation, which
computed the hash but never checked it.)

---

## 8. Security monitoring and detection (`monitoring.py`)

Monitoring is deliberately decoupled from the cryptographic path: turning it off reduces
visibility but cannot weaken the protocol. The protocol layers emit structured events to a
`SecurityMonitor`, which appends them to an in-memory ring buffer and, optionally, to a JSON-Lines
log file a SOC could ingest.

**Events:** `session_start`, `session_end`, `login_success`, `login_failure`, `mac_failure`,
`replay_attempt`, `sequence_violation`, `traversal_attempt`, `rate_limited`, `protocol_error`.

**Threshold detection rules (raise alerts):**

| Alert rule | Trigger |
|---|---|
| `brute_force_login` | ≥ 5 `login_failure` events for one username within 60 s |
| `tampering_suspected` | ≥ 3 `mac_failure` events within 30 s (a burst of tag failures looks like active tampering / key confusion) |
| `path_traversal` | any `traversal_attempt` |

`LoginGuard` (§4.6) enforces the *preventive* replay/lockout controls; `SecurityMonitor`
provides the *detective* controls. The two are separate objects with overlapping but distinct
thresholds.

---

## 9. Security considerations and residual risks

- **Forward secrecy — absent.** Session keys ride on RSA key transport. Compromise of the server
  RSA private key retroactively exposes any recorded past session. Mitigation would be an
  ephemeral (EC)DHE handshake.
- **Server authentication — TOFU only.** A pinned SHA-256 fingerprint of the server's public key
  is printed on connect; there is no certificate chain. A first-use MITM who supplies their own
  key is undetected unless the operator compares fingerprints out of band.
- **Sequence-number width.** `sqn` is 16 bits, so a single direction can carry 65 535 messages
  under one key before wrapping. At 1024-byte fragments that is ~64 MiB of file data per
  direction per session — comfortably above the 64 KiB default file-size limit, but a hard
  ceiling a longer-lived session would need to respect (rekey before wrap).
- **Metadata leakage.** Message sizes and timing are unprotected (§1.2).
- **Credential store.** `users.txt` stores only PBKDF2 hashes (100 000 iterations, per-user
  salt) — never plaintext — but it is a flat file, and the demo passwords are intentionally weak.
- **Private key hygiene.** The RSA private key is generated by `generate_keys.py` with file mode
  `600`, is git-ignored, and is never committed. `DEBUG` secret-leaking print statements from the
  original code were removed in favour of an opt-in, secret-redacting tracer (key material is
  reduced to an 8-hex-character SHA-256 fingerprint).

---

## Appendix A — Constants

| Constant | Value |
|---|---|
| `ver` | `0x0100` |
| `rsv` | `0x0000` |
| Header size | 16 bytes |
| MAC / GCM tag size | 12 bytes |
| Nonce size | 8 bytes (`sqn(2) || rnd(6)`) |
| `etk` size | 256 bytes (RSA-2048 ciphertext) |
| Session / temporary key size | 32 bytes (AES-256) |
| Fragment size | 1024 bytes |
| Default file-size limit | 65536 bytes (64 KiB, `2**16`) |
| PBKDF2 iterations | 100 000 |
| PBKDF2 / password salt size | 16 bytes |
| Login timestamp window | ±2 s (`2×10⁹` ns) |
| Replay-cache window | 2 s |
| Brute-force lockout | 5 failures / 60 s → 60 s lockout |
| MAC-failure alert threshold | 3 within 30 s |
| Brute-force alert threshold | 5 within 60 s |

## Appendix B — `users.txt` record format

One record per line, colon-separated; passwords are never stored in plaintext:

```
username : pwdhash_hex : icount : salt_hex : rootdir
```

- `pwdhash_hex` — PBKDF2-HMAC-SHA256 digest (32 bytes, hex).
- `icount` — PBKDF2 iteration count (100000 for the demo users).
- `salt_hex` — per-user 16-byte salt (hex).
- `rootdir` — the user's root directory, relative to the server root (e.g. `alice/`).

## Appendix C — Operational entry points

- **`server/server.py`** — `--host --port --private-key --users --rootdir --log`. Threaded
  (one thread per connection), loads the RSA private key once, and shares a single `LoginGuard`
  and `SecurityMonitor` across connections. Defaults: `127.0.0.1:5150`.
- **`client/client.py`** — `--host --port --public-key`. Prints the server public-key SHA-256
  fingerprint (TOFU pinning) on connect, then presents a `cmd.Cmd` shell
  (`pwd/ls/cd/mkd/del/upl/dnl/bye`).
- **`generate_keys.py`** — writes `server/keys/private_key.pem` (mode `600`) and
  `client/keys/public_key.pem`, prints the SHA-256 fingerprint of the public key's DER encoding,
  and supports `--passphrase` to encrypt the private key at rest. Keys are git-ignored.
