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
- Content-addressed requests (ADR-0001).
- DSSE + Ed25519 signing with a detached ceremony (ADR-0002).
- Hash-chained ledger and signed Merkle checkpoints with consistency
  verification (ADR-0003).
- Storage protocols (`EventStore`, `ProjectionStore`, `IdempotencyStore`),
  in-memory reference implementations, and the `approvo.testing`
  conformance suite (ADR-0004).
- Declarative policy engine (ADR-0005).
- Canonical JSON (ADR-0006).
- Reserve-then-complete idempotency (ADR-0007).
- One hash chain per `log_id` (ADR-0008).
- Rebuildable, non-authoritative projections (ADR-0009).

See the [Architecture Decision Records](https://michael-swartz.github.io/approvo/adr/)
for the reasoning behind each.

[Unreleased]: https://github.com/Michael-Swartz/approvo/commits/main
