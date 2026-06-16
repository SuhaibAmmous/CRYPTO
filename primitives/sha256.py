import struct
from typing import List

# First 32 bits of the fractional parts of the cube roots of the first 64
# primes (FIPS 180-4, section 4.2.2).
_K: List[int] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# First 32 bits of the fractional parts of the square roots of the first 8
# primes (FIPS 180-4, section 5.3.3).
_H0: List[int] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

_MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """Rotate a 32-bit word right by n bits."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _shr(x: int, n: int) -> int:
    """Logical right shift on a 32-bit word."""
    return (x >> n) & _MASK32


class SHA256:
    """Incremental SHA-256 implementation (FIPS 180-4)."""

    block_size = 64   # bytes (512 bits)
    digest_size = 32  # bytes (256 bits)

    def __init__(self, data: bytes = b"") -> None:
        self._h = list(_H0)
        self._buffer = b""        # not-yet-processed tail (< 64 bytes)
        self._msg_len = 0         # total message length in bytes
        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHA256":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._msg_len += len(data)
        self._buffer += bytes(data)
        # Process every complete 64-byte block currently buffered.
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]
        return self