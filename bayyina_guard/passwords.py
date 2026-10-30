"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import unicodedata

N = 2**14
R = 8
P = 5
DKLEN = 32
SALT_LEN = 16
MAXMEM = 64 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    if not text or not text.isascii():
        raise ValueError("bad base64")
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _normalise(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    password = unicodedata.normalize("NFKC", password)
    if not 8 <= len(password) <= 128:
        raise ValueError("password must be 8 to 128 characters")
    return password


def _parse(stored):
    """Return (n, r, p, salt, key) or None if anything is wrong. Never raises."""
    try:
        if not isinstance(stored, str):
            return None
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return None
        n, r, p = (int(x) for x in parts[1:4])
        salt = _b64decode(parts[4])
        key = _b64decode(parts[5])
    except (ValueError, binascii.Error):
        return None
    if not (2 <= n <= 2**20 and n & (n - 1) == 0):
        return None
    if not 1 <= r <= 32:
        return None
    if not 1 <= p <= 16:
        return None
    if len(salt) < SALT_LEN or len(key) != DKLEN:
        return None
    return n, r, p, salt, key


def hash_password(password: str) -> str:
    password = _normalise(password)
    salt = os.urandom(SALT_LEN)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt, n=N, r=R, p=P, dklen=DKLEN, maxmem=MAXMEM,
    )
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse(stored)
    if parsed is None:
        return False
    try:
        password = _normalise(password)
    except (TypeError, ValueError):
        return False
    n, r, p, salt, key = parsed
    try:
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt, n=n, r=r, p=p, dklen=DKLEN, maxmem=MAXMEM,
        )
    except (ValueError, MemoryError, OverflowError):
        return False
    return hmac.compare_digest(candidate, key)


def needs_rehash(stored: str) -> bool:
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _key = parsed
    return n < N or r < R or p < P