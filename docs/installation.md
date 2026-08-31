# Installation

## Requirements

- **Python ≥ 3.11**
- One runtime dependency: [`cryptography`](https://cryptography.io/)

That's the whole footprint. No database driver, no web framework, no
async runtime beyond the standard library.

## From PyPI

```bash
pip install approvo
```

## From source

```bash
pip install "git+https://github.com/Michael-Swartz/approvo"
```

## Optional extras

| Extra | Pulls in | When you need it |
|---|---|---|
| `approvo[dev]` | `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff` | Running the [store conformance suite](storage.md#the-conformance-suite) against your own `EventStore` / `ProjectionStore` / `IdempotencyStore` |
| `approvo[docs]` | `mkdocs-material`, `mkdocstrings` | Building this documentation site locally |

```bash
pip install "approvo[dev]"
```

## Verifying the install

```python
import approvo
print(approvo.__version__)

from approvo import ApprovalService, Ed25519Signer, KeyDirectory
from approvo.stores import EventStore
```

If those imports succeed you have everything. Head to
[Getting started](getting-started.md).

## Supported versions

approvo is tested on CPython 3.11, 3.12, and 3.13 on every push. It is
pure Python and has no compiled components of its own (`cryptography`
ships wheels for all mainstream platforms).

## Pinning

approvo follows [SemVer](https://semver.org/). Wire formats
(`canonical_bytes` output, `entry_hash` inputs, `to_dict` shapes) are part
of the public API and are versioned with `schema` strings — a change to
any of them is a major version bump. Pin a major:

```
approvo>=0.1,<0.2      # pre-1.0: pin the minor
```
