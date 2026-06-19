 
from .hmac import hmac_sha256

_HASH_LEN = 32  # SHA-256 output length in bytes


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: turn (possibly weak) input keying material into a PRK.

    If `salt` is empty, RFC 5869 specifies a string of HashLen zero bytes.
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * _HASH_LEN
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: stretch a PRK into `length` bytes of output keying material."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * _HASH_LEN:
        raise ValueError("length too large (max 255 * HashLen)")

    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF: extract then expand. Returns `length` bytes."""
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)
