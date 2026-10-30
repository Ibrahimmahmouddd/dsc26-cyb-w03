"""Upload validation. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

BIDI = set("\u061c\u200e\u200f") | {chr(c) for c in range(0x202A, 0x202F)} | {
    chr(c) for c in range(0x2066, 0x206A)
}
TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
SIGNATURES = {"pdf": b"%PDF-", "docx": b"PK\x03\x04"}
MATTER_RE = re.compile(r"MAT-[0-9]{4}-[0-9]{5}")


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(errors)
        self.errors = errors


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(name):
    """Return (display_name, extension, error)."""
    if not isinstance(name, str):
        return None, None, "filename must be a string"
    name = unicodedata.normalize("NFC", name)
    if not 1 <= len(name) <= 120:
        return None, None, "filename must be 1 to 120 characters"
    for ch in name:
        if unicodedata.category(ch) == "Cc" or ch in BIDI:
            return None, None, "filename has control or bidi characters"
    if "/" in name or "\\" in name or ".." in name:
        return None, None, "filename has path characters"
    if name.startswith("."):
        return None, None, "filename must not start with a dot"
    if "." not in name:
        return None, None, "filename needs an extension"
    base, ext = name.rsplit(".", 1)
    ext = ext.lower()
    if ext not in TYPES:
        return None, None, "extension must be pdf or docx"
    if not base.strip():
        return None, None, "filename needs a name before the extension"
    return name, ext, None


def validate_upload(meta: dict) -> CleanUpload:
    errors: dict[str, str] = {}

    display, ext, err = _check_filename(meta.get("filename"))
    if err:
        errors["filename"] = err

    ctype = meta.get("content_type")
    if not isinstance(ctype, str):
        errors["content_type"] = "content_type must be a string"
    elif ext is not None and ctype != TYPES[ext]:
        errors["content_type"] = "content_type does not match the extension"

    first = meta.get("first_bytes")
    if not isinstance(first, bytes):
        errors["first_bytes"] = "first_bytes must be bytes"
    elif ext is not None and not first.startswith(SIGNATURES[ext]):
        errors["first_bytes"] = "file signature does not match the extension"

    size = meta.get("size_bytes")
    if type(size) is not int or not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = "size_bytes must be an integer from 1 to MAX_BYTES"

    matter = meta.get("matter_id")
    if not isinstance(matter, str) or not matter.isascii() or not MATTER_RE.fullmatch(matter):
        errors["matter_id"] = "matter_id must look like MAT-1234-12345"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=uuid.uuid4().hex + "." + ext,
        display_name=display,
        extension=ext,
        content_type=TYPES[ext],
        size_bytes=size,
        matter_id=matter,
    )