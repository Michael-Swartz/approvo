"""Canonical JSON serialization and content hashing.

Every signature and hash in approvo is computed over the canonical byte
form of a JSON object: UTF-8, keys sorted, compact separators, no floats.
If two objects have the same canonical bytes they *are* the same object —
this is what makes requests content-addressed and replays detectable.

The rules are a strict subset of RFC 8785 (JCS):
- Only ``dict``/``list``/``str``/``int``/``bool``/``None`` are allowed.
- Floats are rejected outright (no cross-platform stable representation
  worth gambling an audit trail on). Use strings or ints.
- Dict keys must be strings.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ZERO_HASH = "sha256:" + "0" * 64


class NotCanonicalizable(TypeError):
    """Raised when a value cannot be canonically serialized."""


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise NotCanonicalizable(f"float at {path}: floats are not canonicalizable")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise NotCanonicalizable(f"non-string key at {path}: {k!r}")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise NotCanonicalizable(f"unsupported type {type(value).__name__} at {path}")


def canonical_bytes(obj: Any) -> bytes:
    """Serialize *obj* to its unique canonical byte form."""
    _check(obj, "$")
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical bytes of *obj*."""
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
