 

import struct
import socket

_LEN_PREFIX = 4
_MAX_FRAME = 16 * 1024 * 1024  # 16 MiB sanity cap


class TransportError(Exception):
    """Raised on connection loss or malformed framing."""


def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send one length-prefixed frame."""
    if len(data) > _MAX_FRAME:
        raise TransportError("frame too large")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise if the peer closes early."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise TransportError("connection closed by peer")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive one length-prefixed frame and return its payload."""
    header = _recv_exact(sock, _LEN_PREFIX)
    (length,) = struct.unpack(">I", header)
    if length > _MAX_FRAME:
        raise TransportError("declared frame length too large")
    return _recv_exact(sock, length)
