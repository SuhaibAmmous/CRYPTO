import pathlib

# Pre-shared key — loaded from psk.hex (not committed to git).
# To generate a new one: python -c "import secrets; print(secrets.token_hex(32))" > psk.hex
_PSK_FILE = pathlib.Path(__file__).parent / "psk.hex"
try:
    PSK: bytes = bytes.fromhex(_PSK_FILE.read_text().strip())
except FileNotFoundError:
    raise SystemExit(
        "ERROR: psk.hex not found. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" > psk.hex"
    )

# Party identities, used in the handshake transcript and message headers.
CLIENT_ID: bytes = b"alice-client"
SERVER_ID: bytes = b"bob-server"

# Protocol version. The string is bound into the handshake transcript; the
# single byte is carried in every message header (as authenticated data).
PROTOCOL_VERSION: bytes = b"SecureChannel/1.0"
PROTOCOL_VERSION_BYTE: int = 0x01

# Networking defaults.
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 9999
