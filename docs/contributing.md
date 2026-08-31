# Contributing

The canonical copy of this lives in
[`CONTRIBUTING.md`](https://github.com/Michael-Swartz/approvo/blob/main/CONTRIBUTING.md)
in the repo.

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev,docs]'
.venv/bin/pytest
.venv/bin/mkdocs serve      # docs at http://127.0.0.1:8000
```

## Ground rules

- **`cryptography` is the only runtime dependency.** A new runtime
  dependency needs an ADR and a strong reason.
- **No database adapters in this repo**
  ([ADR-0004](adr/0004-datastore-agnostic.md)). Store implementations live
  in downstream packages; here we maintain the protocols, the conformance
  suite, and the in-memory reference only.
- **Wire-format changes are breaking.** If you change what
  `canonical_bytes` produces, what feeds an `entry_hash`, or any
  `to_dict` shape, bump the relevant `schema` string and update the
  golden vectors in `tests/test_canonical.py` on purpose.
- **Every store-protocol invariant needs a conformance test** in
  `src/approvo/testing.py` (`approvo.testing`).
- `ruff check src/ tests/` and `pytest` must pass. `mkdocs build
  --strict` must pass if you touched docs.

## Architecture decisions

Non-trivial design changes get an [ADR](adr/index.md) in `docs/adr/`,
numbered, following the Context / Decision / Consequences format. ADRs are
immutable once accepted — supersede rather than edit.

## Pull requests

- One logical change per PR.
- Reference the ADR or issue in the description.
- CI runs the test suite on Python 3.11–3.13, `ruff`, and a strict docs
  build.

## Reporting security issues

Open a GitHub security advisory, or email the address in
`pyproject.toml`. Don't file public issues for suspected vulnerabilities.
See [Security model](security.md).
