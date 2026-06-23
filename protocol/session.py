 

import struct
from typing import Tuple

from primitives import chacha20_poly1305 as aead

MSG_CHAT = 0
MSG_CLOSE = 1


class SessionError(Exception):
    """Raised on replay, reorder, decryption failure, or malformed records."""


def _xor_nonce(nonce_base: bytes, seq: int) -> bytes:
    """12-byte nonce = nonce_base XOR (seq in the low 8 bytes)."""
    seq_bytes = b"\x00\x00\x00\x00" + struct.pack(">Q", seq)  # 12 bytes
    return bytes(a ^ b for a, b in zip(nonce_base, seq_bytes))


class Session:
    """Bidirectional secure session bound to one socket peer."""

    def __init__(self, role: str, keys, version_byte: int):
        if role not in ("client", "server"):
            raise SessionError("role must be 'client' or 'server'")
        self.role = role
        self.version_byte = version_byte & 0xFF

        if role == "client":
            self._send_key = keys.key_c2s
            self._send_nonce = keys.nonce_base_c2s
            self._recv_key = keys.key_s2c
            self._recv_nonce = keys.nonce_base_s2c
            self._my_id = keys.client_id
            self._peer_id = keys.server_id
        else:
            self._send_key = keys.key_s2c
            self._send_nonce = keys.nonce_base_s2c
            self._recv_key = keys.key_c2s
            self._recv_nonce = keys.nonce_base_c2s
            self._my_id = keys.server_id
            self._peer_id = keys.client_id

        self._send_seq = 0
        self._last_recv_seq = -1  # so the first accepted sequence is 0

    # --- header helpers --------------------------------------------------
    def _build_header(self, msg_type: int, seq: int) -> bytes:
        if len(self._my_id) > 255:
            raise SessionError("sender id too long")
        return (
            struct.pack(">BBB", self.version_byte, msg_type & 0xFF, len(self._my_id))
            + self._my_id
            + struct.pack(">Q", seq)
        )

    @staticmethod
    def _parse_header(header: bytes):
        if len(header) < 3:
            raise SessionError("truncated header")
        version_byte, msg_type, id_len = struct.unpack(">BBB", header[:3])
        if len(header) != 3 + id_len + 8:
            raise SessionError("malformed header length")
        sender_id = header[3:3 + id_len]
        (seq,) = struct.unpack(">Q", header[3 + id_len:])
        return version_byte, msg_type, sender_id, seq

    # --- send / receive --------------------------------------------------
    def encrypt(self, plaintext: bytes, msg_type: int = MSG_CHAT) -> bytes:
        """Produce one wire record for `plaintext`. Advances the send sequence."""
        seq = self._send_seq
        header = self._build_header(msg_type, seq)
        nonce = _xor_nonce(self._send_nonce, seq)
        ciphertext = aead.encrypt(self._send_key, nonce, plaintext, aad=header)
        self._send_seq += 1
        # record = header_len(2) || header || ciphertext+tag
        return struct.pack(">H", len(header)) + header + ciphertext

    def decrypt(self, record: bytes) -> Tuple[int, bytes]:
        """Verify and decrypt one wire record. Returns (msg_type, plaintext).

        Raises SessionError on replay, reorder, wrong sender, or bad tag.
        """
        if len(record) < 2:
            raise SessionError("truncated record")
        (hlen,) = struct.unpack(">H", record[:2])
        if len(record) < 2 + hlen:
            raise SessionError("truncated record header")
        header = record[2:2 + hlen]
        ciphertext = record[2 + hlen:]

        version_byte, msg_type, sender_id, seq = self._parse_header(header)

        if version_byte != self.version_byte:
            raise SessionError("protocol version mismatch")
        if sender_id != self._peer_id:
            raise SessionError("unexpected sender identity")
        # Replay / reorder protection: sequence must strictly increase.
        if seq <= self._last_recv_seq:
            raise SessionError(
                "replay or out-of-order record (seq=%d, last=%d)"
                % (seq, self._last_recv_seq)
            )

        nonce = _xor_nonce(self._recv_nonce, seq)
        try:
            plaintext = aead.decrypt(self._recv_key, nonce, ciphertext, aad=header)
        except aead.AEADError as exc:
            raise SessionError("authentication failed: %s" % exc)

        # Only commit the sequence after successful authentication.
        self._last_recv_seq = seq
        return msg_type, plaintext
