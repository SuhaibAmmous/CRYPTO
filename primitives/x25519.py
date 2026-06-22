import os

_P = (1 << 255) - 19          # field prime 2^255 - 19
_A24 = 121665                 # (486662 - 2) / 4
_BITS = 255
_BASE_U = 9                   # standard base point u-coordinate


def _decode_little_endian(b: bytes, bits: int = _BITS) -> int:
    """Decode up to `bits` bits of a little-endian byte string into an int."""
    total = 0
    for i in range((bits + 7) // 8):
        total |= b[i] << (8 * i)
    return total


def _decode_u_coordinate(u: bytes) -> int:
    """Decode a u-coordinate, masking the unused top bit (RFC 7748 5)."""
    if len(u) != 32:
        raise ValueError("u-coordinate must be 32 bytes")
    u_list = bytearray(u)
    # 255-bit field: clear the most significant bit of the last byte.
    u_list[31] &= (1 << (_BITS % 8)) - 1 if (_BITS % 8) else 0xFF
    return _decode_little_endian(bytes(u_list), _BITS)


def _encode_u_coordinate(u: int) -> bytes:
    """Encode a field element as a 32-byte little-endian string."""
    u %= _P
    return u.to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    """Decode and clamp a scalar (RFC 7748 5: decodeScalar25519)."""
    if len(k) != 32:
        raise ValueError("scalar must be 32 bytes")
    k_list = bytearray(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return _decode_little_endian(bytes(k_list), 256)


def _cswap(swap: int, a: int, b: int):
    """Constant-time conditional swap of a and b when swap == 1."""
    dummy = (-swap) & (a ^ b)   # mask is all-ones when swap == 1, else zero
    return a ^ dummy, b ^ dummy


def _scalar_mult(k_int: int, u_int: int) -> int:
    """Montgomery-ladder scalar multiplication (RFC 7748 5)."""
    x1 = u_int
    x2, z2 = 1, 0
    x3, z3 = u_int, 1
    swap = 0

    for t in range(_BITS - 1, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = (((da + cb) % _P) ** 2) % _P
        z3 = (x1 * (((da - cb) % _P) ** 2)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (_A24 * e) % _P) % _P)) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    # Return x2 * z2^(p-2) mod p  (modular inverse via Fermat's little theorem).
    return (x2 * pow(z2, _P - 2, _P)) % _P


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """The X25519 function: scalar * u, all as 32-byte little-endian strings."""
    k_int = _decode_scalar(scalar)
    u_int = _decode_u_coordinate(u_coordinate)
    result = _scalar_mult(k_int, u_int)
    return _encode_u_coordinate(result)


def generate_private_key() -> bytes:
    """Generate a random 32-byte X25519 private key (clamping is applied on use)."""
    return os.urandom(32)


def derive_public_key(private_key: bytes) -> bytes:
    """Compute the public key for a private key: X25519(private, base point 9)."""
    base = _encode_u_coordinate(_BASE_U)
    return x25519(private_key, base)


def compute_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Compute the ECDH shared secret with a peer's public key."""
    return x25519(private_key, peer_public_key)
