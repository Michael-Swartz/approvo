"""DSSE envelopes (https://github.com/secure-systems-lab/dsse).

A decision travels as a DSSE envelope: the canonical payload bytes plus
one or more detached signatures over the PAE (Pre-Authentication
Encoding) of the payload type and body. PAE prevents confusion attacks
where the same bytes are interpreted under a different payload type.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from ..canonical import canonical_bytes


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.standard_b64decode(data)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding."""
    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type)).encode(),
            payload_type.encode(),
            str(len(payload)).encode(),
            payload,
        ]
    )


def wrap(payload: Any, payload_type: str, signers: list) -> dict:
    """Canonicalize *payload* and sign it with every (synchronous) signer."""
    body = canonical_bytes(payload)
    signable = pae(payload_type, body)
    return {
        "payloadType": payload_type,
        "payload": _b64(body),
        "signatures": [{"keyid": s.key_id(), "sig": _b64(s.sign(signable))} for s in signers],
    }


async def wrap_async(payload: Any, payload_type: str, signers: list) -> dict:
    """Like :func:`wrap`, but awaits signers that sign over the network (KMS)."""
    from .signer import sign_with

    body = canonical_bytes(payload)
    signable = pae(payload_type, body)
    signatures = []
    for s in signers:
        sig, keyid = await sign_with(s, signable)
        signatures.append({"keyid": keyid, "sig": _b64(sig)})
    return {"payloadType": payload_type, "payload": _b64(body), "signatures": signatures}


def unwrap_payload(envelope: dict) -> Any:
    """Decode the payload without verifying. Callers must verify separately."""
    return json.loads(_b64d(envelope["payload"]))


def signable_bytes(envelope: dict) -> bytes:
    return pae(envelope["payloadType"], _b64d(envelope["payload"]))
