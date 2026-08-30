# Errors

Every failure mode a caller might branch on has its own type, so a
backend can map exceptions to HTTP status codes without string matching.

## Suggested HTTP mapping

| Exception | HTTP |
|---|---|
| `RequestNotFound`, `UnknownPolicy` | 404 |
| `SubjectConstraintViolation` | 422 |
| `PolicyMismatch`, `IdempotencyConflict` | 409 |
| `ConcurrencyExhausted` (after retries) | 503 |
| `ChallengeExpired`, `RequestExpired` | 410 |
| `SignatureInvalid` | 400 |
| `KeyNotAuthorized`, `KeyExpiredOrRevoked`, `SeparationOfDutiesViolation` | 403 |
| `StoreError` | 502 / 503 |
| `LedgerTampered` (any subtype), `VerificationFailed` | 500 + alert a human |

## Hierarchy

::: approvo.errors
    options:
      show_root_heading: false
      members_order: source
      filters: []
