# SecureChannel

**ENCS4320 — Applied Cryptography · Course Project**

A complete secure communication system implemented **from scratch in pure
Python**. Two parties establish a shared secret over an insecure TCP network,
mutually authenticate using a pre-shared key, and exchange messages with
**confidentiality, integrity, and authenticity** — including authenticated
associated data and replay protection.

All cryptographic primitives are implemented directly from their official
RFC / FIPS specifications. No external or standard-library crypto modules
(`hashlib`, `hmac`, `secrets`, …) are used anywhere in the implementation.

---

## Team Members

| Name | ID |
|------|----|
| Mohammad Manasrah | 1211407 |
| Suhaib Ammous | 1222517 |

---

## What it does

**Phase A — Handshake (key establishment & authentication)**

1. Each party generates an ephemeral **X25519** key pair (RFC 7748).
2. Public keys are exchanged over TCP.
3. Each party computes the **ECDH** shared secret.
4. **Authentication:** each party computes `HMAC(PSK, transcript)` where
   `transcript = client_pub || server_pub || client_id || server_id ||
   protocol_version`. Each side verifies the peer's tag in constant time.
   A mismatch aborts the connection — this binds the ephemeral keys to the
   two legitimate PSK holders and defeats man-in-the-middle attacks.
5. **HKDF** (RFC 5869, `salt = PSK`, `ikm = shared_secret`) derives two
   independent directional session keys (client→server and server→client)
   plus per-direction nonce material.

**Phase B — Secure messaging (AEAD channel)**

6. Every message is protected with **ChaCha20-Poly1305** AEAD (RFC 8439).
7. Each message carries a plaintext header (protocol version, message type,
   sender ID, sequence number) used as **associated data** — authenticated
   but not encrypted. Tampering with the header makes decryption fail.
8. **Replay protection:** strictly increasing sequence numbers are bound into
   the nonce and the associated data; any replayed or out-of-order record is
   rejected.
9. A simple interactive command-line chat loop provides send/receive.

---

## Implemented primitives

| Component | Specification | File |
|-----------|---------------|------|
| SHA-256 | FIPS 180-4 | `primitives/sha256.py` |
| HMAC | RFC 2104 | `primitives/hmac.py` |
| HKDF (extract + expand) | RFC 5869 | `primitives/hkdf.py` |
| ChaCha20 | RFC 8439 | `primitives/chacha20.py` |
| Poly1305 | RFC 8439 | `primitives/poly1305.py` |
| ChaCha20-Poly1305 AEAD | RFC 8439 §2.8 | `primitives/chacha20_poly1305.py` |
| X25519 | RFC 7748 | `primitives/x25519.py` |

Every primitive is validated against the **official test vectors** published
in its RFC/FIPS document (see `tests/`).

---

## Project structure

```
SecureChannel/
├── primitives/        # cryptographic primitives, pure Python from scratch
│   ├── sha256.py
│   ├── hmac.py
│   ├── hkdf.py
│   ├── chacha20.py
│   ├── poly1305.py
│   ├── chacha20_poly1305.py
│   └── x25519.py
├── protocol/          # the SecureChannel protocol
│   ├── transport.py   # length-prefixed TCP framing
│   ├── handshake.py   # Phase A: ECDH + PSK auth + HKDF
│   └── session.py     # Phase B: AEAD records + replay protection
├── tests/             # official RFC/FIPS test vectors
│   ├── test_sha256.py
│   ├── test_hmac.py
│   ├── test_hkdf.py
│   ├── test_chacha20.py
│   ├── test_poly1305.py
│   ├── test_chacha20_poly1305.py
│   └── test_x25519.py
├── main.py            # CLI entry point (--role server|client)
├── config.py          # identities, version, host/port; loads PSK from psk.hex
├── psk.hex            # pre-shared key (hex); git-ignored — generate locally
├── requirements.txt   # no third-party packages; documents stdlib-only dependency
└── README.md
```

---

## Requirements

- Python 3.8 or newer. No third-party packages are needed.

---

## How to run

Both peers must use the **same `psk.hex`** file. Identities and networking
defaults live in `config.py`.

**0. Generate the pre-shared key** (once, copy the file to both machines):

```bash
python -c "import secrets; print(secrets.token_hex(32))" > psk.hex
```

**1. Start the server** (in one terminal):

```bash
python main.py --role server
```

**2. Start the client** (in another terminal):

```bash
python main.py --role client --host 127.0.0.1
```

Optional flags: `--host <addr>` and `--port <n>` (defaults come from
`config.py`: `127.0.0.1:9999`).

Once the handshake completes you'll see
`handshake complete — keys derived, peer authenticated`. Type a message and
press Enter to send; incoming messages print as they arrive. Type `/quit`
(or send EOF / Ctrl-D) to end the session cleanly.

---

## How to run the tests

From the project root:

```bash
# Run the whole suite
python -m unittest discover -s tests -p "test_*.py" -v

# Or run a single primitive's vectors
python tests/test_chacha20.py
```

A primitive that does not pass its official test vectors is considered not
implemented; all primitives in this project pass.

---

## Design notes

- **No nonce reuse.** Each direction has its own 32-byte key and 12-byte
  nonce base. The per-record 96-bit nonce is `nonce_base XOR sequence_number`,
  so within a direction no nonce is ever reused, and the two directions use
  different keys regardless.
- **Authenticated headers.** The header (version, type, sender, sequence) is
  passed as AEAD associated data, so it is integrity-protected without being
  encrypted. A flipped sequence number or sender ID causes the Poly1305 tag
  check to fail.
- **Constant-time tag comparison.** Both the handshake auth tag and the AEAD
  tag are compared with a custom constant-time routine (`compare_digest` in
  `primitives/hmac.py`) to avoid timing side channels.
- **Low-order key rejection.** An all-zero ECDH result (which a low-order
  peer public key would produce) aborts the handshake.
- **Randomness.** Ephemeral private keys come from `os.urandom`
  (`secrets` is forbidden by the project rules; `os` is permitted).
- **`threading`** is used only in `main.py` to run the interactive chat
  (concurrent send/receive). It is not a cryptographic dependency.

---

## Mapping to the official specifications

- SHA-256 — NIST FIPS 180-4, §5–6
- HMAC — RFC 2104 (also FIPS 198-1); test vectors from RFC 4231
- HKDF — RFC 5869 (extract-then-expand)
- ChaCha20, Poly1305, AEAD — RFC 8439 (intermediate values & vectors)
- X25519 — RFC 7748, §4–5 (Montgomery ladder, vectors in §5.2 / §6.1)