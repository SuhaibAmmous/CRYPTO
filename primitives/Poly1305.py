_P = (1 << 130) - 5          # 2^130 - 5
_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
_2_128 = 1 << 128


def _le_bytes_to_int(data: bytes) -> int:
   
    n = 0
    for i, byte in enumerate(data):
        n |= byte << (8 * i)
    return n


def poly1305_mac(message: bytes, key: bytes) -> bytes:
   
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r = _le_bytes_to_int(key[0:16]) & _CLAMP
    s = _le_bytes_to_int(key[16:32])

    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        # Append the "1" bit just past the most-significant byte of the block.
        n = _le_bytes_to_int(block) + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % _P

    acc = (acc + s) % _2_128
    # Serialize the low 128 bits as little-endian.
    return acc.to_bytes(16, "little")
