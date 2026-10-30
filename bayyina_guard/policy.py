"""Document access policy. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    id: str
    role: str                       # partner | associate | paralegal | client | auditor
    client_id: str | None = None
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False


@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal"
    legal_hold: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


ROLE_ACTIONS = {
    "partner": {"read", "comment", "upload_version", "delete", "share_external"},
    "associate": {"read", "comment", "upload_version"},
    "paralegal": {"read", "upload_version"},
    "client": {"read", "comment"},
    "auditor": set(),
}
ACTIONS = {"read", "comment", "upload_version", "delete", "share_external"}


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    if user is None or not user.id:
        return _deny("unauthenticated")
    if not isinstance(action, str) or action not in ACTIONS:
        return _deny("unknown_action")
    if not isinstance(user.role, str) or user.role not in ROLE_ACTIONS:
        return _deny("unknown_role")
    if action == "delete" and doc.legal_hold:
        return _deny("legal_hold")
    if action not in ROLE_ACTIONS[user.role]:
        return _deny("role_not_permitted")
    if user.role == "client":
        if user.client_id is None or user.client_id != doc.client_id:
            return _deny("tenant_mismatch")
    if user.role in ("associate", "paralegal"):
        if doc.matter_id not in user.matters:
            return _deny("not_assigned")
    normal = doc.confidentiality == "normal"
    if user.role in ("client", "paralegal") and not normal:
        return _deny("restricted")
    if (not normal or action == "share_external") and user.mfa is not True:
        return _deny("mfa_required")
    return Decision(True, "ok")


