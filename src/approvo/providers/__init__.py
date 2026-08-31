"""Optional KMS/HSM key providers.

Each submodule implements :class:`approvo.crypto.keyprovider.KeyProvider`
against one backend and imports its SDK lazily, so importing the module
without the SDK is fine — only construction fails, with an install hint.

Install the matching extra::

    pip install 'approvo[gcpkms]'   # google-cloud-kms
    pip install 'approvo[awskms]'   # aioboto3
    pip install 'approvo[vault]'    # hvac

Then::

    from approvo.providers.gcpkms import GcpKmsKeyProvider
    from approvo.crypto import CompositeKeyProvider, LocalFileKeyProvider

    provider = CompositeKeyProvider([
        GcpKmsKeyProvider(),
        LocalFileKeyProvider(root="/etc/approvo/keys"),
    ])

Validate any provider with
:class:`approvo.testing.KeyProviderConformance`.
"""

from __future__ import annotations

__all__ = ["AwsKmsKeyProvider", "GcpKmsKeyProvider", "VaultTransitKeyProvider"]


def __getattr__(name: str):  # lazy re-export without importing SDKs eagerly
    if name == "GcpKmsKeyProvider":
        from .gcpkms import GcpKmsKeyProvider

        return GcpKmsKeyProvider
    if name == "AwsKmsKeyProvider":
        from .awskms import AwsKmsKeyProvider

        return AwsKmsKeyProvider
    if name == "VaultTransitKeyProvider":
        from .vault import VaultTransitKeyProvider

        return VaultTransitKeyProvider
    raise AttributeError(name)
