# Signing back ends

Task-oriented guide: [Signing](../signing.md).

## Algorithm registry

::: approvo.crypto.algorithms
    options:
      members:
        - get_scheme
        - register_scheme
        - known_schemes
        - keyid_for
        - Scheme

## Signers

::: approvo.crypto.signer.sign_with

::: approvo.crypto.signer.public_key_ref

::: approvo.crypto.signer.PublicKeyMaterial

## KeyProvider

::: approvo.crypto.keyprovider.KeyProvider

::: approvo.crypto.keyprovider.parse_key_ref

::: approvo.crypto.keyprovider.InMemoryKeyProvider

::: approvo.crypto.keyprovider.LocalFileKeyProvider

::: approvo.crypto.keyprovider.EnvKeyProvider

::: approvo.crypto.keyprovider.CompositeKeyProvider

::: approvo.crypto.keyprovider.KeyDescriptor

## KeyResolver

::: approvo.crypto.resolver.SigningPurpose

::: approvo.crypto.resolver.SigningContext

::: approvo.crypto.resolver.KeyResolver

::: approvo.crypto.resolver.StaticKeyResolver

::: approvo.crypto.resolver.TemplateKeyResolver

## SigningService

::: approvo.crypto.signing.SigningService

::: approvo.crypto.signing.TrustSpec

## Cloud providers (optional extras)

::: approvo.providers.gcpkms.GcpKmsKeyProvider

::: approvo.providers.awskms.AwsKmsKeyProvider

::: approvo.providers.vault.VaultTransitKeyProvider
