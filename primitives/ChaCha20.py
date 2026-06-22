import struct
from typing import List

_MASK32 = 0xFFFFFFFF

# "expand 32-byte k" interpreted as four little-endian 32-bit words.
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _quarter_round(s: List[int], a: int, b: int, c: int, d: int) -> None:
    
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] ^= s[a]
    s[d] = _rotl32(s[d], 16)

    s[c] = (s[c] + s[d]) & _MASK32
    s[b] ^= s[c]
    s[b] = _rotl32(s[b], 12)

    s[a] = (s[a] + s[b]) & _MASK32
    s[d] ^= s[a]
    s[d] = _rotl32(s[d], 8)

    s[c] = (s[c] + s[d]) & _MASK32
    s[b] ^= s[c]
    s[b] = _rotl32(s[b], 7)


def _build_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    state = list(_CONSTANTS)
    state += list(struct.unpack("<8I", key))
    state.append(counter & _MASK32)
    state += list(struct.unpack("<3I", nonce))
    return state


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
   
    state = _build_state(key, counter, nonce)
    working = list(state)

    # 20 rounds = 10 iterations of (4 column + 4 diagonal) quarter-rounds.
    for _ in range(10):
        # column rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        # diagonal rounds
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    # Add the working state to the original state (mod 2^32).
    out_words = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out_words)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
 
    out = bytearray(len(data))
    block_counter = counter
    for offset in range(0, len(data), 64):
        keystream = chacha20_block(key, block_counter, nonce)
        chunk = data[offset:offset + 64]
        for i, byte in enumerate(chunk):
            out[offset + i] = byte ^ keystream[i]
        block_counter = (block_counter + 1) & _MASK32
    return bytes(out)


# Encryption and decryption are the same operation for a stream cipher.
chacha20_decrypt = chacha20_encrypt
