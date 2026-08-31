"""``KeyResolver`` — which key signs what.

This is where "org-level keys" lives. A resolver maps a signing purpose
plus context to a logical key reference that a
:class:`~approvo.crypto.keyprovider.KeyProvider` understands.

Cheapest first:

- :class:`StaticKeyResolver` — one key per purpose. "The org key signs
  every decision; the log key signs every checkpoint."
- :class:`TemplateKeyResolver` — substitute ``{log_id}`` / ``{purpose}``
  / ``{kind}`` into a reference template. One key per environment/tenant.
- Write your own for anything else (per team from ``policy_id``, …).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from ..errors import KeyResolutionError


class SigningPurpose(str, Enum):
    DECISION = "decision"
    CHECKPOINT = "checkpoint"


@dataclass(frozen=True)
class SigningContext:
    log_id: str
    purpose: SigningPurpose
    kind: str | None = None
    policy_id: str | None = None
    approver_id: str | None = None


@runtime_checkable
class KeyResolver(Protocol):
    async def resolve(self, ctx: SigningContext) -> str: ...


class StaticKeyResolver:
    """One key reference per :class:`SigningPurpose`."""

    def __init__(self, mapping: dict[SigningPurpose, str]) -> None:
        self._mapping = dict(mapping)

    async def resolve(self, ctx: SigningContext) -> str:
        try:
            return self._mapping[ctx.purpose]
        except KeyError:
            raise KeyResolutionError(
                f"no key configured for purpose {ctx.purpose.value!r}"
            ) from None

    def purposes(self) -> dict[SigningPurpose, str]:
        return dict(self._mapping)


class TemplateKeyResolver:
    """Format a reference template per purpose with fields from the context.

    ::

        TemplateKeyResolver({
            SigningPurpose.DECISION:
                "gcpkms://.../cryptoKeys/{log_id}-approvals/cryptoKeyVersions/1",
            SigningPurpose.CHECKPOINT:
                "gcpkms://.../cryptoKeys/{log_id}-log/cryptoKeyVersions/1",
        })
    """

    def __init__(self, templates: dict[SigningPurpose, str]) -> None:
        self._templates = dict(templates)

    async def resolve(self, ctx: SigningContext) -> str:
        try:
            tmpl = self._templates[ctx.purpose]
        except KeyError:
            raise KeyResolutionError(
                f"no template for purpose {ctx.purpose.value!r}"
            ) from None
        try:
            return tmpl.format(
                log_id=ctx.log_id,
                purpose=ctx.purpose.value,
                kind=ctx.kind or "",
                policy_id=ctx.policy_id or "",
                approver_id=ctx.approver_id or "",
            )
        except KeyError as e:  # unknown placeholder in the template
            raise KeyResolutionError(f"template references unknown field {e}") from None
