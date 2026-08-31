# Contributing

## Setup

```console
python -m venv .venv
.venv/bin/pip install -e '.[dev,docs]'
.venv/bin/pytest
```

## Ground rules

- **`cryptography` is the only runtime dependency.** New runtime deps need
  an ADR and a strong reason.
- **No database adapters in this repo** ([ADR-0004](docs/adr/0004-datastore-agnostic.md)).
  Store implementations live in downstream packages; here we only maintain
  the protocols, the conformance suite, and the in-memory reference.
- **Wire-format changes are breaking.** If you change what
  `canonical_bytes` produces, what goes into an `entry_hash`, or any
  `to_dict` shape, bump the relevant `schema` string and update the golden
  vectors in `tests/test_canonical.py` deliberately.
- **Every store-protocol invariant needs a conformance test** in
  `src/approvo/testing.py` (`approvo.testing`).
- `ruff check src/ tests/` and `pytest` must pass. `mkdocs build --strict`
  must pass if you touched docs.

## Architecture decisions

Non-trivial design changes get an ADR in `docs/adr/`, numbered, following
the existing format (Context / Decision / Consequences). ADRs are
immutable once accepted; supersede rather than edit.

## Commits & PRs

- One logical change per PR.
- Reference the ADR or issue in the description.
- CI runs tests on 3.11–3.13, lint, and a strict docs build.
