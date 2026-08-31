"""Public key material and the key directory.

A :class:`KeyRef` is a public key plus its owner, its *use*, and its
validity window. The :class:`KeyDirectory` is the trust root at
verification time: a signature only counts if its keyid resolves to a key
that was valid *at the moment the decision was made* (not at verification
time — an approval signed with a then-valid, later-rotated key stays
valid).

``scheme`` **is** the signature algorithm id — one of
:func:`approvo.crypto.algorithms.known_schemes` (``ed25519``,
``ecdsa-p256-sha256``, …).

``key_use`` says what a key is *allowed* to sign:

- ``approver`` — a specific person's own key. A decision it signs counts
  as that person (``owner_id``) approving.
- ``decision_issuer`` — a server/org custodial key. A decision it signs
  counts as ``decision.approver_id`` approving, *on the strength of the
  server's authentication*. Scope it with ``log_ids``.
- ``log`` — signs checkpoints for the logs in ``log_ids`` (or all logs
  when ``log_ids`` is ``None``).
- ``oidc_issuer`` — reserved for token-bound decisions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..clock import parse_rfc3339
from .algorithms import ED25519, get_scheme, keyid_for

__all__ = ["KEY_USES", "KeyDirectory", "KeyRef", "keyid_for"]

KEY_USES = ("approver", "decision_issuer", "log", "oidc_issuer")


@dataclass(frozen=True)
class KeyRef:
    keyid: str  # sha256 hex of the scheme's canonical public bytes
    scheme: str  # signature algorithm id, e.g. "ed25519", "ecdsa-p256-sha256"
    public: str  # hex-encoded canonical public bytes for `scheme`
    owner_id: str  # Identity.id this key signs for (or a service id)
    not_before: str  # RFC 3339
    not_after: str | None = None
    revoked_at: str | None = None
    key_use: str = "approver"  # one of KEY_USES
    log_ids: tuple[str, ...] | None = None  # None => every log

    def valid_at(self, at_time: str) -> bool:
        t = parse_rfc3339(at_time)
        if t < parse_rfc3339(self.not_before):
            return False
        if self.not_after is not None and t > parse_rfc3339(self.not_after):
            return False
        if self.revoked_at is not None and t >= parse_rfc3339(self.revoked_at):  # noqa: SIM103
            return False
        return True

    def scoped_to(self, log_id: str) -> bool:
        return self.log_ids is None or log_id in self.log_ids

    def public_bytes(self) -> bytes:
        return bytes.fromhex(self.public)

    def load_public(self) -> object:
        return get_scheme(self.scheme).load_public(self.public_bytes())

    def to_dict(self) -> dict:
        return {
            "keyid": self.keyid,
            "scheme": self.scheme,
            "public": self.public,
            "owner_id": self.owner_id,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "revoked_at": self.revoked_at,
            "key_use": self.key_use,
            "log_ids": list(self.log_ids) if self.log_ids is not None else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> KeyRef:
        log_ids = d.get("log_ids")
        return cls(
            keyid=d["keyid"],
            scheme=d.get("scheme", ED25519),
            public=d["public"],
            owner_id=d["owner_id"],
            not_before=d["not_before"],
            not_after=d.get("not_after"),
            revoked_at=d.get("revoked_at"),
            key_use=d.get("key_use", "approver"),
            log_ids=tuple(log_ids) if log_ids is not None else None,
        )


class KeyDirectory:
    """keyid -> KeyRef. The verifier's trust root."""

    def __init__(self, keys: list[KeyRef] | None = None) -> None:
        self._keys: dict[str, KeyRef] = {k.keyid: k for k in (keys or [])}

    def add(self, key: KeyRef) -> None:
        self._keys[key.keyid] = key

    def extend(self, keys: list[KeyRef]) -> None:
        for k in keys:
            self._keys[k.keyid] = k

    def get(self, keyid: str) -> KeyRef | None:
        return self._keys.get(keyid)

    def revoke(self, keyid: str, revoked_at: str) -> None:
        key = self._keys[keyid]
        self._keys[keyid] = KeyRef.from_dict({**key.to_dict(), "revoked_at": revoked_at})

    def all(self) -> list[KeyRef]:
        return list(self._keys.values())

    def by_use(self, key_use: str) -> list[KeyRef]:
        return [k for k in self._keys.values() if k.key_use == key_use]

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
