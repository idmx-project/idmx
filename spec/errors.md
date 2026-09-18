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
| `rate_limited` | R, P | 429 | temporary | yes, honor `Retry-After` / `retry_after` | never |
| `mailbox_full` | P | — | temporary | yes | never |
| `temporary_failure` | R, P | 503 | temporary | yes | after fallback window (R only); never (P) |

- `unsupported_version` is the answer to any path under an unknown major
  version (e.g. `/v2/...`). Senders avoid it by selecting a version from the
  capabilities `versions` list (`discovery.md` §5).
- Permanent per-recipient problems make the result `rejected`; temporary ones
  make it `deferred`.
- Senders MUST treat an unknown problem `type` by its HTTP status class: 4xx
  permanent, 5xx temporary; inside a result, by the result `status`.
- A 5xx without a problem document, a connection failure, or a TLS failure is
  handled as `temporary_failure`. So is a capabilities document that cannot be
  fetched or is invalid (`capabilities.md` §5).

## 3. Fallback rule

- IDMX advertised but unreachable / 5xx: **retry IDMX with backoff for the
  fallback window (§3.1), then fall back to SMTP**. This is the only case that
  falls back: a connection failure, a TLS failure, or a request-level 5xx.
- **Any other authenticated IDMX answer never falls back**: 4xx problems
  (including `rate_limited`) and every per-recipient
  result (`rejected` or `deferred`, including `mailbox_full`). SMTP must not
  bypass a deliberate IDMX rejection or throttle, and a full mailbox is just as
  full over SMTP. Temporary ones are retried over IDMX until give-up (§3.1).
- A valid pin does **not** forbid this fallback (`discovery.md` §3.2).
- **Exception — no common major version** (`unsupported_version`, or a
  `versions` list without any version the sender supports): the sender MAY
  fall back to SMTP immediately, even while a pin is valid. The receiver has
  not rejected the message; the two systems merely share no IDMX version, which
  is equivalent to the domain not supporting IDMX for this sender.

### 3.1 Retry schedule

One schedule covers request-level temporary failures and deferred recipients
(`delivery.md` §5.3). All times count from the **first delivery attempt** of
the message to that recipient domain.

| Parameter | Value |
|---|---|
| First retry | 1 min after the first attempt |
| Backoff | delay doubles per attempt, capped at **1 h** |
| Jitter | each delay SHOULD be randomized by ±20 % |
| Fallback window | SHOULD be **2 h**; MUST be within 1–4 h in production use |
| Give-up | **5 days**, then bounce (RFC 3464 DSN to the envelope sender) |

- `Retry-After` (request level) and `retry_after` (per recipient) are a **lower
  bound**: the next attempt happens at the later of the scheduled time and the
  time the receiver asked for.
- SMTP fallback happens at the first attempt time at or after the end of the
  fallback window, if every attempt so far ended in a fallback-eligible failure
  (§3). A non-eligible temporary answer (e.g. `rate_limited`) proves the
  endpoint is alive; the sender keeps retrying IDMX.
- After handing the message to SMTP, the sender makes no further IDMX attempts
  for it.
- Give-up (5 days) lies inside the 7-day idempotency-key limit
  (`delivery.md` §4).

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
- Abuse-report contact: `abuse_contact` in capabilities, a `mailto:` URI
  (`capabilities.md` §3).
- Reputation and filtering stay receiver-local policy.
