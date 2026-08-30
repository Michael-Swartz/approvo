# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public scaffold.
- `ApprovalService` — async, store-injected: `create_request`,
  `submit_decision`, detached signing via `prepare_decision` /
  `submit_signed_decision`, `get_status`, `get_view` / `query`,
  `checkpoint`, `verify`, `rebuild_projections`.
- Content-addressed requests ([ADR-0001](docs/adr/0001-content-addressed-requests.md)).
- DSSE + Ed25519 signing with a detached ceremony
  ([ADR-0002](docs/adr/0002-dsse-ed25519-detached-signing.md)).
- Hash-chained ledger and signed Merkle checkpoints with consistency
  verification ([ADR-0003](docs/adr/0003-hash-chain-merkle-checkpoints.md)).
- Storage protocols (`EventStore`, `ProjectionStore`, `IdempotencyStore`),
  in-memory reference implementations, and the `approvo.testing`
  conformance suite ([ADR-0004](docs/adr/0004-datastore-agnostic.md)).
- Declarative policy engine ([ADR-0005](docs/adr/0005-declarative-policy-engine.md)).
- Canonical JSON ([ADR-0006](docs/adr/0006-canonical-json.md)).
- Reserve-then-complete idempotency ([ADR-0007](docs/adr/0007-idempotency.md)).

[Unreleased]: https://github.com/Michael-Swartz/approvo/commits/main
