import pytest

from approvo.canonical import NotCanonicalizable, canonical_bytes, canonical_hash

# Golden vectors: changing serialization breaks every existing signature.
# If one of these fails, you have broken compatibility — bump the schema
# version, do not "fix" the vector.
GOLDEN = [
    ({}, b"{}", "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    (
        {"b": 1, "a": [True, None, "x"]},
        b'{"a":[true,null,"x"],"b":1}',
        "sha256:54a65415ad370228851a1da4b31b6fd42dc58b19a50d35cae759325f7388ce64",
    ),
]


@pytest.mark.parametrize("obj,expected_bytes,expected_hash", GOLDEN)
def test_golden_bytes(obj, expected_bytes, expected_hash):
    assert canonical_bytes(obj) == expected_bytes
    assert canonical_hash(obj) == expected_hash


def test_key_order_is_irrelevant():
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})


def test_unicode_is_stable():
    assert canonical_bytes({"k": "héllo"}) == '{"k":"héllo"}'.encode()


def test_floats_rejected():
    with pytest.raises(NotCanonicalizable):
        canonical_bytes({"x": 1.5})


def test_non_string_keys_rejected():
    with pytest.raises(NotCanonicalizable):
        canonical_bytes({1: "x"})


def test_unsupported_types_rejected():
    with pytest.raises(NotCanonicalizable):
        canonical_bytes({"x": object()})
