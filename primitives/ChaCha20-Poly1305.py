import struct

from .chacha20 import chacha20_block, chacha20_encrypt
from .poly1305 import poly1305_mac
from .hmac import compare_digest


class AEADError(Exception):
    """Raised when authentication fails during AEAD decryption."""


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Derive the one-time Poly1305 key from the ChaCha20 keystream (counter 0)."""
    block = chacha20_block(key, 0, nonce)
    return block[0:32]


def _pad16(data: bytes) -> bytes:
    """Zero padding to the next 16-byte boundary (empty if already aligned)."""
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def _build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD-encrypt. Returns ciphertext || 16-byte tag."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    otk = _poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    tag = poly1305_mac(_build_mac_data(aad, ciphertext), otk)
    return ciphertext + tag


def decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """AEAD-decrypt and verify. Returns plaintext, or raises AEADError."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(ciphertext_and_tag) < 16:
        raise AEADError("ciphertext too short to contain a tag")

    ciphertext = ciphertext_and_tag[:-16]
    received_tag = ciphertext_and_tag[-16:]

    otk = _poly1305_key_gen(key, nonce)
    expected_tag = poly1305_mac(_build_mac_data(aad, ciphertext), otk)

    if not compare_digest(received_tag, expected_tag):
        raise AEADError("authentication tag mismatch")

    return chacha20_encrypt(key, 1, nonce, ciphertext)
