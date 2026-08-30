"""Public key material and the key directory.

A :class:`KeyRef` is a public key plus its owner and validity window.
The :class:`KeyDirectory` is the trust root at verification time: a
signature only counts if its keyid resolves to a key that was valid
*at the moment the decision was made* (not at verification time — an
approval signed with a then-valid, later-rotated key stays valid).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ..clock import parse_rfc3339


def keyid_for(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()


@dataclass(frozen=True)
class KeyRef:
    keyid: str  # sha256 hex of raw public key bytes
    scheme: str  # "ed25519"
    public: str  # hex-encoded raw public key bytes
    owner_id: str  # Identity.id this key signs for
    not_before: str  # RFC 3339
    not_after: str | None = None
    revoked_at: str | None = None

    def valid_at(self, at_time: str) -> bool:
        t = parse_rfc3339(at_time)
        if t < parse_rfc3339(self.not_before):
            return False
        if self.not_after is not None and t > parse_rfc3339(self.not_after):
            return False
        if self.revoked_at is not None and t >= parse_rfc3339(self.revoked_at):  # noqa: SIM103
            return False
        return True

    def public_bytes(self) -> bytes:
        return bytes.fromhex(self.public)

    def to_dict(self) -> dict:
        return {
            "keyid": self.keyid,
            "scheme": self.scheme,
            "public": self.public,
            "owner_id": self.owner_id,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "revoked_at": self.revoked_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> KeyRef:
        return cls(
            keyid=d["keyid"],
            scheme=d["scheme"],
            public=d["public"],
            owner_id=d["owner_id"],
            not_before=d["not_before"],
            not_after=d.get("not_after"),
            revoked_at=d.get("revoked_at"),
        )


class KeyDirectory:
    """keyid -> KeyRef. The verifier's trust root."""

    def __init__(self, keys: list[KeyRef] | None = None) -> None:
        self._keys: dict[str, KeyRef] = {k.keyid: k for k in (keys or [])}

    def add(self, key: KeyRef) -> None:
        self._keys[key.keyid] = key

    def get(self, keyid: str) -> KeyRef | None:
        return self._keys.get(keyid)

    def revoke(self, keyid: str, revoked_at: str) -> None:
        key = self._keys[keyid]
        self._keys[keyid] = KeyRef(**{**key.to_dict(), "revoked_at": revoked_at})

    def all(self) -> list[KeyRef]:
        return list(self._keys.values())

    def to_dict(self) -> dict:
        return {"keys": [k.to_dict() for k in self._keys.values()]}

    @classmethod
    def from_dict(cls, d: dict) -> KeyDirectory:
        return cls([KeyRef.from_dict(k) for k in d.get("keys", ())])

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> KeyDirectory:
        return cls.from_dict(json.loads(Path(path).read_text()))
