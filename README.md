# SecureChannel

**ENCS4320 — Applied Cryptography (Term 1252)**  
Birzeit University — Faculty of Engineering and Technology

---

## Team Members

| Name | ID |
|------|----|
| Mohammad Manasrah | 1211407 |
| Suhaib Ammous | 1222517 |

---

## Description

SecureChannel is a secure peer-to-peer communication application implemented
in pure Python from scratch, without any external cryptographic libraries.

Two parties establish an authenticated encrypted channel over TCP using
modern cryptographic primitives (X25519, ChaCha20-Poly1305, HKDF, HMAC-SHA-256)
— the same primitives used in TLS 1.3, Signal, and WireGuard.

> Full documentation, protocol design, and run instructions will be added
> as implementation progresses.

---

## Project Structure

```
SecureChannel/
├── primitives/      # Cryptographic primitives (from scratch)
├── protocol/        # Handshake and secure messaging logic
├── tests/           # Official RFC/FIPS test vectors
├── main.py          # Entry point (--role server | client)
├── config.py        # Constants and PSK placeholder
```
