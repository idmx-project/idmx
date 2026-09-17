# IDMX Errors, Retries, and SMTP Fallback

Status: **draft skeleton**. Decisions copied from `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17).
License: CC-BY-4.0 (see `LICENSE`).

## 1. Error model

Errors are **RFC 9457 problem details** (`application/problem+json`).
`type` = `https://idmx-project.org/problems/<identifier>`.

## 2. Error identifiers

| Identifier | Class | Retry IDMX | SMTP fallback |
|---|---|---|---|
| `recipient_not_found` | permanent | no | never |
| `invalid_signature` | permanent | no | never |
| `unsupported_version` | permanent | no | TODO |
| `unsupported_feature` | permanent | no | TODO |
| `message_too_large` | permanent | no | never |
| `policy_rejected` | permanent | no | never |
| `rate_limited` | temporary | yes, honor `Retry-After` | TODO |
| `temporary_failure` | temporary | yes | after fallback window |

TODO: confirm table; HTTP status code per identifier.

## 3. Fallback rule

- IDMX advertised but unreachable / 5xx: **retry IDMX with backoff for a
  bounded window (order of 1–4 h), then fall back to SMTP**.
- Explicit IDMX rejections (4xx-class semantic errors) **never fall back**.
  SMTP must not bypass a deliberate IDMX rejection.

TODO: exact retry schedule and fallback window value.

## 4. Idempotency

- `Idempotency-Key` is required and covers the whole delivery.
- Duplicates return the original result. See `signing.md` §3.

## 5. Multi-recipient results

One POST per recipient domain; response carries a **per-recipient result array**.

TODO: per-recipient result schema and partial-failure retry rules.

## 6. Bounces / DSN

- Maximize synchronous validation before 2xx (recipient exists, quota, policy).
- Post-acceptance failures: classic **RFC 3464 DSN delivered as a normal message**.
  No new async mechanism in v1.

## 7. Size limits

- Receiver advertises `max_message_size` in `GET /v1/capabilities`.
- Spec mandates a floor (e.g. ≥ 25 MB). Over limit → `message_too_large`.
- No chunked/resumable upload in v1.

TODO: floor value.

## 8. Abuse hooks (v1)

- `rate_limited` / `policy_rejected` with `Retry-After`.
- Abuse-report contact advertised via capabilities.
- Reputation and filtering stay receiver-local policy.

TODO: abuse-report contact format.
