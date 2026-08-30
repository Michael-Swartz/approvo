# Data models

All models are frozen dataclasses with `to_dict()` / `from_dict()`
converters that produce and consume canonicalizable JSON.

## Domain

::: approvo.models.Identity

::: approvo.models.ApprovalRequest

::: approvo.models.Decision

::: approvo.models.Record

## Ledger

::: approvo.models.LedgerEntry

::: approvo.models.Checkpoint

## Policy results

::: approvo.models.PolicyResult

## Read models (projections)

::: approvo.models.RequestView

::: approvo.models.RequestQuery

::: approvo.models.Page

## Detached signing

::: approvo.models.DecisionChallenge

## Verification

::: approvo.models.Check

::: approvo.models.VerificationReport
