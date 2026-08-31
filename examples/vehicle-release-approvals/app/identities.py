"""Demo identities, keys, and policy for the vehicle-release approval system.

This mirrors the "3 things you hold" from the approvo getting-started
guide: a key directory, an identity roster, and a policy. Everything here
is generated in-process on startup purely so the example is runnable with
no external setup beyond MongoDB — a real deployment would issue keys to
each approver's own device and never let the server hold their private
key material (see ``docs/signing.md`` and ``docs/getting-started.md`` in
the main repo for the detached-signing ceremony this example simplifies).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from approvo import Ed25519Signer, Identity, InMemoryPolicyStore, KeyDirectory, Policy, to_rfc3339

# Subject fields every vehicle software release request must carry.
REQUIRED_SUBJECT_FIELDS = ("ecu", "artifact_digest", "version", "vehicle_platform")

RELEASE_POLICY_ID = "vehicle-release-v1"


@dataclass(frozen=True)
class DemoIdentity:
    identity: Identity
    signer: Ed25519Signer


@dataclass(frozen=True)
class Bootstrap:
    key_dir: KeyDirectory
    identities: dict[str, Identity]
    signers: dict[str, Ed25519Signer]
    policy_store: InMemoryPolicyStore
    log_signer: Ed25519Signer


def build_bootstrap() -> Bootstrap:
    now = to_rfc3339(datetime.now(timezone.utc))

    demo_identities = [
        DemoIdentity(Identity("user:priya", ("safety-engineer",)), Ed25519Signer.generate()),
        DemoIdentity(Identity("user:noah", ("qa",)), Ed25519Signer.generate()),
        DemoIdentity(Identity("user:sam", ("release-engineer",)), Ed25519Signer.generate()),
    ]
    log_signer = Ed25519Signer.generate()

    keys = KeyDirectory()
    for demo in demo_identities:
        keys.add(demo.signer.public_key_ref(demo.identity.id, not_before=now))
    keys.add(log_signer.public_key_ref("log:vehicle-releases", not_before=now, key_use="log"))

    policy = Policy(
        id=RELEASE_POLICY_ID,
        kind="vehicle-software-release",
        allowed_approvers=("role:safety-engineer", "role:qa"),
        threshold=2,
        require_distinct_roles=("safety-engineer", "qa"),
        required_subject_fields=REQUIRED_SUBJECT_FIELDS,
    )

    return Bootstrap(
        key_dir=keys,
        identities={d.identity.id: d.identity for d in demo_identities},
        signers={d.identity.id: d.signer for d in demo_identities},
        policy_store=InMemoryPolicyStore([policy]),
        log_signer=log_signer,
    )
