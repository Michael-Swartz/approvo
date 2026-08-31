"""The optional KMS provider modules must import without their SDKs installed.

Construction requires the SDK (and raises a helpful ImportError); import
must not, so the classes are documentable and discoverable.
"""

import importlib

import pytest


@pytest.mark.parametrize(
    "module,cls",
    [
        ("approvo.providers.gcpkms", "GcpKmsKeyProvider"),
        ("approvo.providers.awskms", "AwsKmsKeyProvider"),
        ("approvo.providers.vault", "VaultTransitKeyProvider"),
    ],
)
def test_provider_module_imports(module, cls):
    mod = importlib.import_module(module)
    assert hasattr(mod, cls)


def test_providers_lazy_reexport():
    import approvo.providers as p

    assert set(p.__all__) == {
        "AwsKmsKeyProvider",
        "GcpKmsKeyProvider",
        "VaultTransitKeyProvider",
    }
    # attribute access triggers the submodule import
    assert p.GcpKmsKeyProvider.__name__ == "GcpKmsKeyProvider"
