"""AWS KMS key provider.

    pip install 'approvo[awskms]'      # for a bundled aioboto3 client

Key references are ``awskms://`` + a key id, alias, or ARN::

    awskms://arn:aws:kms:us-east-1:123456789012:key/abcd-1234
    awskms://alias/approvo-org-approvals

You may pass your own client (``aioboto3`` session client, or a plain
``boto3`` client — sync calls are detected and used as-is). If none is
given, an ``aioboto3`` client is created lazily.

KMS ``KeySpec`` -> approvo scheme: ``ECC_NIST_P256`` → ``ecdsa-p256-sha256``,
``ECC_NIST_P384`` → ``ecdsa-p384-sha384``, ``RSA_*`` → ``rsa-pss-sha256``.
"""

from __future__ import annotations

from ..crypto.keyprovider import _BaseProvider, parse_key_ref
from ..crypto.signer import PublicKeyMaterial, Signer
from ..errors import KeyProviderError
from ._common import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    RSA_PSS_SHA256,
    RemoteSigner,
    _maybe_await,
)

_KEYSPEC_MAP = {
    "ECC_NIST_P256": (ECDSA_P256_SHA256, "ECDSA_SHA_256"),
    "ECC_NIST_P384": (ECDSA_P384_SHA384, "ECDSA_SHA_384"),
    "RSA_2048": (RSA_PSS_SHA256, "RSASSA_PSS_SHA_256"),
    "RSA_3072": (RSA_PSS_SHA256, "RSASSA_PSS_SHA_256"),
    "RSA_4096": (RSA_PSS_SHA256, "RSASSA_PSS_SHA_256"),
}


class _Aioboto3ClientFactory:
    def __init__(self, region_name: str | None = None) -> None:
        self._region = region_name
        self._ctx = None
        self._client = None

    async def get(self):
        if self._client is None:
            try:
                import aioboto3  # type: ignore
            except ImportError as e:  # pragma: no cover
                raise ImportError(
                    "aioboto3 is required (or pass client=). "
                    "Install with: pip install 'approvo[awskms]'"
                ) from e
            session = aioboto3.Session()
            self._ctx = session.client("kms", region_name=self._region)
            self._client = await self._ctx.__aenter__()
        return self._client


class AwsKmsKeyProvider(_BaseProvider):
    schemes = ("awskms",)

    def __init__(self, client=None, *, region_name: str | None = None) -> None:
        self._client = client
        self._factory = None if client is not None else _Aioboto3ClientFactory(region_name)

    async def _kms(self):
        if self._client is not None:
            return self._client
        return await self._factory.get()

    @staticmethod
    def _key_id(key_ref: str) -> str:
        _, rest = parse_key_ref(key_ref)
        if not rest:
            raise KeyProviderError(f"empty awskms key id in {key_ref!r}")
        return rest

    async def _describe(self, key_ref: str) -> tuple[str, str, bytes]:
        kms = await self._kms()
        key_id = self._key_id(key_ref)
        resp = await _maybe_await(kms.get_public_key(KeyId=key_id))
        spec = resp["KeySpec"]
        try:
            scheme, signing_algo = _KEYSPEC_MAP[spec]
        except KeyError:
            raise KeyProviderError(f"unsupported KMS KeySpec {spec}") from None
        return scheme, signing_algo, bytes(resp["PublicKey"])  # DER SPKI

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        scheme, _algo, spki = await self._describe(key_ref)
        return PublicKeyMaterial(scheme=scheme, public=spki)

    async def get_signer(self, key_ref: str) -> Signer:
        scheme, signing_algo, spki = await self._describe(key_ref)
        key_id = self._key_id(key_ref)
        get_kms = self._kms

        async def _raw_sign(data: bytes) -> bytes:
            kms = await get_kms()
            resp = await _maybe_await(
                kms.sign(
                    KeyId=key_id,
                    Message=data,
                    MessageType="RAW",
                    SigningAlgorithm=signing_algo,
                )
            )
            return bytes(resp["Signature"])

        return RemoteSigner(scheme=scheme, public=spki, raw_sign=_raw_sign, key_ref=key_ref)
