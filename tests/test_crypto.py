from approvo import Ed25519Signer, KeyDirectory
from approvo.crypto.envelope import pae, unwrap_payload, wrap
from approvo.crypto.verifier import verify_envelope

T = "2026-08-30T12:00:00.000Z"
EARLY = "2025-01-01T00:00:00.000Z"


def test_pae_matches_dsse_spec_example():
    assert (
        pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def make_kd(signer, owner="user:alice", **kw):
    kd = KeyDirectory()
    kd.add(signer.public_key_ref(owner, not_before="2026-01-01T00:00:00.000Z", **kw))
    return kd


def test_wrap_verify_roundtrip():
    signer = Ed25519Signer.generate()
    env = wrap({"hello": "world"}, "test/v1", [signer])
    assert verify_envelope(env, make_kd(signer), at_time=T) == ["user:alice"]
    assert unwrap_payload(env) == {"hello": "world"}


def test_tampered_payload_fails():
    signer = Ed25519Signer.generate()
    env = wrap({"verdict": "reject"}, "test/v1", [signer])
    evil = wrap({"verdict": "approve"}, "test/v1", [signer])
    env["payload"] = evil["payload"]  # swap body, keep original signature? no:
    env["signatures"] = wrap({"verdict": "reject"}, "test/v1", [signer])["signatures"]
    assert verify_envelope(env, make_kd(signer), at_time=T) == []


def test_payload_type_confusion_fails():
    signer = Ed25519Signer.generate()
    env = wrap({"x": 1}, "type-a/v1", [signer])
    env["payloadType"] = "type-b/v1"
    assert verify_envelope(env, make_kd(signer), at_time=T) == []


def test_key_not_yet_valid():
    signer = Ed25519Signer.generate()
    assert verify_envelope(wrap({"x": 1}, "t/v1", [signer]), make_kd(signer), at_time=EARLY) == []


def test_expired_key():
    signer = Ed25519Signer.generate()
    kd = make_kd(signer, not_after="2026-06-01T00:00:00.000Z")
    assert verify_envelope(wrap({"x": 1}, "t/v1", [signer]), kd, at_time=T) == []


def test_revoked_key():
    signer = Ed25519Signer.generate()
    kd = make_kd(signer)
    kd.revoke(signer.key_id(), revoked_at="2026-07-01T00:00:00.000Z")
    assert verify_envelope(wrap({"x": 1}, "t/v1", [signer]), kd, at_time=T) == []
    # but a signature made *before* revocation still verifies at that time
    assert verify_envelope(
        wrap({"x": 1}, "t/v1", [signer]), kd, at_time="2026-06-01T00:00:00.000Z"
    ) == ["user:alice"]


def test_signer_file_roundtrip(tmp_path):
    signer = Ed25519Signer.generate()
    signer.save(tmp_path / "k.key")
    loaded = Ed25519Signer.from_file(tmp_path / "k.key")
    assert loaded.key_id() == signer.key_id()
