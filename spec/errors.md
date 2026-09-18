# IDMX Errors, Retries, and SMTP Fallback

Status: **draft skeleton**. Decisions copied from `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17).
License: CC-BY-4.0 (see `LICENSE`).

## 1. Error model

Errors are **RFC 9457 problem details** (`application/problem+json`).
`type` = `https://idmx-project.org/problems/<identifier>`.

## 2. Error identifiers

"Level": **R** = request-level problem response (nothing delivered), **P** =
per-recipient `problem` inside a `200` result (`delivery.md` §5).

| Identifier | Level | HTTP status (R) | Class | Retry IDMX | SMTP fallback |
|---|---|---|---|---|---|
| `invalid_request` | R | 400 | permanent | no | never |
| `invalid_signature` | R | 401 | permanent | no | never |
| `policy_rejected` | R, P | 403 | permanent | no | never |
| `recipient_not_found` | P | — | permanent | no | never |
| `unsupported_version` | R | 404 | permanent | no | **allowed**, immediately (§3) |
| `idempotency_conflict` | R | 409 | permanent | no | never |
| `message_too_large` | R | 413 | permanent | no | never |
| `unsupported_feature` | R | 422 | permanent | no | TODO |
| `rate_limited` | R, P | 429 | temporary | yes, honor `Retry-After` / `retry_after` | TODO |
| `mailbox_full` | P | — | temporary | yes | TODO |
| `temporary_failure` | R, P | 503 | temporary | yes | after fallback window (R) |

- `unsupported_version` is the answer to any path under an unknown major
  version (e.g. `/v2/...`). Senders avoid it by selecting a version from the
  capabilities `versions` list (`discovery.md` §5).
- Permanent per-recipient problems make the result `rejected`; temporary ones
  make it `deferred`.
- Senders MUST treat an unknown problem `type` by its HTTP status class: 4xx
  permanent, 5xx temporary; inside a result, by the result `status`.
- A 5xx without a problem document, a connection failure, or a TLS failure is
  handled as `temporary_failure`.

## 3. Fallback rule

- IDMX advertised but unreachable / 5xx: **retry IDMX with backoff for a
  bounded window (order of 1–4 h), then fall back to SMTP**.
- Explicit IDMX rejections (4xx-class semantic errors) **never fall back**.
  SMTP must not bypass a deliberate IDMX rejection.
- **Exception — no common major version** (`unsupported_version`, or a
  `versions` list without any version the sender supports): the sender MAY
  fall back to SMTP immediately, even while a pin is valid. The receiver has
  not rejected the message; the two systems merely share no IDMX version, which
  is equivalent to the domain not supporting IDMX for this sender.

TODO: exact retry schedule and fallback window value.

## 4. Idempotency

See `delivery.md` §4. Duplicates return the original response; a reused key
with different content → `idempotency_conflict`.

## 5. Multi-recipient results

See `delivery.md` §5: always `200` with a per-recipient result array once the
request itself is acceptable. Deferred recipients are retried as a new
delivery with a new idempotency key.

## 6. Bounces / DSN

- Maximize synchronous validation before 2xx (recipient exists, quota, policy).
- Post-acceptance failures: classic **RFC 3464 DSN delivered as a normal message**.
  No new async mechanism in v1.

## 7. Size limits

- Receiver advertises `max_message_size` in `GET /v1/capabilities`.
- Every receiver MUST accept at least **25 MiB** (26 214 400 bytes) of request
  body; there is no upper limit. Over limit → `message_too_large`.
- No chunked/resumable upload in v1 (`delivery.md` §7.2 sketches the future).

## 8. Abuse hooks (v1)

- `rate_limited` / `policy_rejected` with `Retry-After`.
- Abuse-report contact advertised via capabilities.
- Reputation and filtering stay receiver-local policy.

TODO: abuse-report contact format.
