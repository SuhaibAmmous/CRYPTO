 

import socket
from typing import NamedTuple

from primitives import x25519
from primitives.hmac import hmac_sha256, compare_digest
from primitives.hkdf import hkdf_extract, hkdf_expand
from .transport import send_frame, recv_frame, TransportError

# HKDF output layout: 32 + 32 + 12 + 12 = 88 bytes.
_KEY_LEN = 32
_NONCE_LEN = 12
_OKM_LEN = 2 * _KEY_LEN + 2 * _NONCE_LEN
_HKDF_INFO = b"SecureChannel directional keys v1"


class HandshakeError(Exception):
    """Raised when the handshake fails (auth mismatch, bad data, etc.)."""


class SessionKeys(NamedTuple):
    """Derived key material plus context, ready to build a Session."""
    key_c2s: bytes        # client -> server encryption key
    key_s2c: bytes        # server -> client encryption key
    nonce_base_c2s: bytes
    nonce_base_s2c: bytes
    client_id: bytes
    server_id: bytes


def _build_transcript(client_pub: bytes, server_pub: bytes,
                      client_id: bytes, server_id: bytes,
                      version: bytes) -> bytes:
    """Deterministic transcript, identical on both sides regardless of role."""
    return client_pub + server_pub + client_id + server_id + version


def perform_handshake(sock: socket.socket, role: str, psk: bytes,
                      client_id: bytes, server_id: bytes,
                      version: bytes) -> SessionKeys:
    """Run the full Phase A handshake and return derived SessionKeys.

    `role` must be "client" or "server".
    """
    if role not in ("client", "server"):
        raise HandshakeError("role must be 'client' or 'server'")

    # --- Step 1: ephemeral key pair -------------------------------------
    my_private = x25519.generate_private_key()
    my_public = x25519.derive_public_key(my_private)

    # --- Step 2: exchange public keys -----------------------------------
    if role == "client":
        send_frame(sock, my_public)
        peer_public = recv_frame(sock)
        client_pub, server_pub = my_public, peer_public
    else:  # server
        peer_public = recv_frame(sock)
        send_frame(sock, my_public)
        client_pub, server_pub = peer_public, my_public

    if len(peer_public) != 32:
        raise HandshakeError("peer public key has wrong length")

    # --- Step 3: ECDH shared secret -------------------------------------
    shared_secret = x25519.compute_shared_secret(my_private, peer_public)
    # An all-zero shared secret indicates a low-order/invalid peer key.
    if shared_secret == b"\x00" * 32:
        raise HandshakeError("invalid peer public key (all-zero shared secret)")

    # --- Step 4: PSK authentication over the transcript -----------------
    transcript = _build_transcript(client_pub, server_pub,
                                   client_id, server_id, version)
    my_tag = hmac_sha256(psk, transcript)

    if role == "client":
        send_frame(sock, my_tag)
        peer_tag = recv_frame(sock)
    else:
        peer_tag = recv_frame(sock)
        send_frame(sock, my_tag)

    # Both sides compute the same tag; verifying the peer's tag against ours
    # proves the peer shares the PSK and saw the same ephemeral keys.
    if not compare_digest(my_tag, peer_tag):
        raise HandshakeError("authentication failed: PSK/transcript mismatch")

    # --- Step 5: HKDF key derivation ------------------------------------
    # PSK is the salt; the ECDH shared secret is the input keying material.
    prk = hkdf_extract(psk, shared_secret)
    okm = hkdf_expand(prk, _HKDF_INFO, _OKM_LEN)

    key_c2s = okm[0:32]
    key_s2c = okm[32:64]
    nonce_base_c2s = okm[64:76]
    nonce_base_s2c = okm[76:88]

    return SessionKeys(
        key_c2s=key_c2s,
        key_s2c=key_s2c,
        nonce_base_c2s=nonce_base_c2s,
        nonce_base_s2c=nonce_base_s2c,
        client_id=client_id,
        server_id=server_id,
    )
