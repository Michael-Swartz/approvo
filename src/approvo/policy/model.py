"""Declarative approval policies.

A policy is data, not code: it can be reviewed, signed, versioned, and —
crucially — content-addressed. Requests pin ``policy_digest`` at
creation, so a policy edited after the fact cannot retroactively change
what a recorded approval meant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..canonical import canonical_hash
from ..errors import SubjectConstraintViolation, UnknownPolicy
from ..models import POLICY_SCHEMA


@dataclass(frozen=True)
class Policy:
    id: str
    kind: str  # must match request.kind
    allowed_approvers: tuple[str, ...]  # Identity ids ("user:alice") and/or roles ("role:qa")
    threshold: int  # distinct valid approvals required
    require_distinct_roles: tuple[str, ...] = ()  # e.g. approvals must cover ("qa", "sre")
    separation_of_duties: bool = True  # requester's own approval never counts
    reject_is_terminal: bool = True  # any valid reject => rejected
    max_age_seconds: int = 7 * 24 * 3600  # decision window from request creation
    required_subject_fields: tuple[str, ...] = ()  # e.g. ("artifact_digest", "version")
    schema: str = POLICY_SCHEMA

    @property
    def digest(self) -> str:
        return canonical_hash(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "id": self.id,
            "kind": self.kind,
            "allowed_approvers": list(self.allowed_approvers),
            "threshold": self.threshold,
            "require_distinct_roles": list(self.require_distinct_roles),
            "separation_of_duties": self.separation_of_duties,
            "reject_is_terminal": self.reject_is_terminal,
            "max_age_seconds": self.max_age_seconds,
            "required_subject_fields": list(self.required_subject_fields),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        return cls(
            id=d["id"],
            kind=d["kind"],
            allowed_approvers=tuple(d["allowed_approvers"]),
            threshold=d["threshold"],
            require_distinct_roles=tuple(d.get("require_distinct_roles", ())),
            separation_of_duties=d.get("separation_of_duties", True),
            reject_is_terminal=d.get("reject_is_terminal", True),
            max_age_seconds=d.get("max_age_seconds", 7 * 24 * 3600),
            required_subject_fields=tuple(d.get("required_subject_fields", ())),
            schema=d.get("schema", POLICY_SCHEMA),
        )

    def validate_subject(self, subject: dict) -> None:
        missing = [f for f in self.required_subject_fields if f not in subject]
        if missing:
            raise SubjectConstraintViolation(
                f"subject missing required field(s) for policy {self.id!r}: {missing}"
            )


class PolicyStore(Protocol):
    def get(self, policy_id: str) -> Policy: ...


class InMemoryPolicyStore:
    def __init__(self, policies: list[Policy] | None = None) -> None:
        self._policies = {p.id: p for p in (policies or [])}

    def add(self, policy: Policy) -> None:
        self._policies[policy.id] = policy

    def get(self, policy_id: str) -> Policy:
        try:
            return self._policies[policy_id]
        except KeyError:
            raise UnknownPolicy(policy_id) from None
