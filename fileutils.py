"""Small helpers shared by the SDES file transfer flows (client<->server)."""

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview_hex(data: bytes, num_bytes: int = 32) -> str:
    """Hex dump of the first num_bytes of data, for terminal previews."""
    snippet = data[:num_bytes]
    suffix = " ..." if len(data) > num_bytes else ""
    return snippet.hex(" ") + suffix
