"""KeyProvider: run the shipped conformance suite against the local providers."""

import pytest

from approvo.crypto.keyprovider import (
    CompositeKeyProvider,
    EnvKeyProvider,
    InMemoryKeyProvider,
    LocalFileKeyProvider,
    parse_key_ref,
)
from approvo.crypto.signer import Ed25519Signer
from approvo.errors import KeyProviderError
from approvo.testing import KeyProviderConformance

pytestmark = pytest.mark.asyncio


class TestInMemoryKeyProvider(KeyProviderConformance):
    @pytest.fixture
    def key_provider(self):
        p = InMemoryKeyProvider()
        p.generate("org")
        return p

    @pytest.fixture
    def key_ref(self):
        return "memory://org"


class TestLocalFileKeyProvider(KeyProviderConformance):
    @pytest.fixture
    def key_provider(self, tmp_path):
        Ed25519Signer.generate().save(tmp_path / "org.key")
        return LocalFileKeyProvider(root=tmp_path)

    @pytest.fixture
    def key_ref(self):
        return "file://org"


class TestEnvKeyProvider(KeyProviderConformance):
    @pytest.fixture
    def key_provider(self):
        seed = Ed25519Signer.generate()._key.private_bytes_raw().hex()
        return EnvKeyProvider(environ={"APPROVO_TEST_KEY": seed})

    @pytest.fixture
    def key_ref(self):
        return "env://APPROVO_TEST_KEY"


# --- provider-specific behavior -------------------------------------------- #


async def test_parse_key_ref():
    assert parse_key_ref("gcpkms://projects/x") == ("gcpkms", "projects/x")
    with pytest.raises(KeyProviderError):
        parse_key_ref("no-scheme-here")


async def test_composite_routes_by_scheme(tmp_path):
    mem = InMemoryKeyProvider()
    mem.generate("a")
    Ed25519Signer.generate().save(tmp_path / "b.key")
    composite = CompositeKeyProvider([mem, LocalFileKeyProvider(root=tmp_path)])

    assert set(composite.schemes) == {"memory", "file"}
    sa = await composite.get_signer("memory://a")
    sb = await composite.get_signer("file://b")
    assert sa.key_id() != sb.key_id()


async def test_composite_unknown_scheme(tmp_path):
    composite = CompositeKeyProvider([InMemoryKeyProvider()])
    with pytest.raises(KeyProviderError):
        await composite.get_signer("gcpkms://whatever")


async def test_composite_list_keys_merges():
    mem1 = InMemoryKeyProvider()
    mem1.generate("a")
    composite = CompositeKeyProvider([mem1])
    keys = await composite.list_keys()
    assert [k.key_ref for k in keys] == ["memory://a"]


async def test_localfile_ensure_generates(tmp_path):
    p = LocalFileKeyProvider(root=tmp_path)
    assert not (tmp_path / "fresh.key").exists()
    p.ensure("file://fresh")
    assert (tmp_path / "fresh.key").exists()
    signer = await p.get_signer("file://fresh")
    assert signer.algorithm == "ed25519"


async def test_localfile_relative_without_root_errors():
    with pytest.raises(KeyProviderError):
        await LocalFileKeyProvider().get_signer("file://rel")


async def test_env_missing_var():
    with pytest.raises(KeyProviderError):
        await EnvKeyProvider(environ={}).get_signer("env://NOPE")


async def test_env_bad_hex():
    with pytest.raises(KeyProviderError):
        await EnvKeyProvider(environ={"K": "not-hex!!"}).get_signer("env://K")
