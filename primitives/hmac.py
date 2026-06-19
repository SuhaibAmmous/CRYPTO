from .sha256 import SHA256, sha256

_BLOCK_SIZE = 64 


def _normalize_key(key: bytes) -> bytes:
    """Reduce/pad the key to exactly one hash block (RFC 2104)."""
    if len(key) > _BLOCK_SIZE:
        key = sha256(key)          # keys longer than block size are hashed
    if len(key) < _BLOCK_SIZE:
        key = key + b"\x00" * (_BLOCK_SIZE - len(key))  # then zero-padded
    return key


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA-256 of `message` under `key`. Returns 32 bytes."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")

    k0 = _normalize_key(bytes(key))
    i_key_pad = bytes(b ^ 0x36 for b in k0)  # K0 XOR ipad
    o_key_pad = bytes(b ^ 0x5C for b in k0)  # K0 XOR opad

    inner = SHA256(i_key_pad + bytes(message)).digest()
    return SHA256(o_key_pad + inner).digest()


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    return hmac_sha256(key, message).hex()


def compare_digest(a: bytes, b: bytes) -> bool:
   
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
