# IDMX Capabilities

Status: **draft**. Baseline: `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17) plus the
capabilities decisions of 2026-09-18 recorded here.
License: CC-BY-4.0 (see `LICENSE`).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
BCP 14 (RFC 2119, RFC 8174).

## 1. Overview

`GET /v1/capabilities` returns a JSON document with the **versions, limits, and
operational parameters** of a receiver. It is unsigned (`signing.md` §1) and
authenticated by TLS 1.3 alone.

- The document describes *how much* and *how long*, never *whether*: every
  conforming v1 receiver implements the same behavior.
- A successful fetch sets or refreshes the sender's discovery pin
  (`discovery.md` §3.1).

## 2. No optional behavior

**IDMX v1 has no optional protocol behavior and no feature flags.** "Supports
IDMX v1" means one thing.

- A capabilities member MUST NOT announce optional protocol behavior. Members
  are limits and operational parameters only.
- New protocol behavior arrives in a new major version, where it is mandatory
  for every implementation of that version (`discovery.md` §5).
- There are no vendor extensions. Senders MUST ignore members they do not know
  and MUST NOT change protocol behavior because of them.

Rationale: optional features turn interoperability into a matrix, push senders
to the lowest common denominator, and make delivery behave differently from one
partner to the next with no visible reason.

## 3. Document

```json
{
  "versions": ["v1"],
  "max_message_size": 52428800,
  "max_recipients": 100,
  "discovery_pin_max_age": 604800,
  "abuse_contact": "mailto:abuse@receiver.example"
}
```

| Member | Type | Requirement |
|---|---|---|
| `versions` | array of strings | All major versions the receiver serves, as URL path segments (`v1`, `v2`, …). Absent = `["v1"]`. See `discovery.md` §5. |
| `max_message_size` | integer | **REQUIRED.** Largest accepted request body in bytes. MUST be ≥ **26 214 400** (25 MiB); no upper limit. See `delivery.md` §6. |
| `max_recipients` | integer | Largest accepted `to` length. Absent = 100. MUST be ≥ 100. See `delivery.md` §6. |
| `discovery_pin_max_age` | integer | Seconds a sender pins the positive discovery result. Absent = 0 = no pin. SHOULD be 604 800. See `discovery.md` §3.1. |
| `abuse_contact` | string | OPTIONAL. Where to report abuse originating from the domains this receiver serves: one **`mailto:` URI** (RFC 6068) without header fields (no `?`). |

- The document is a JSON object, UTF-8, `Content-Type: application/json`.
- Later minor revisions of v1 MAY add members of the same kind (limits,
  operational parameters). Unknown members MUST be ignored.

## 4. Caching

- Receivers SHOULD send `Cache-Control: max-age=3600`.
- Without a usable `Cache-Control` lifetime, senders assume **1 hour**.
- Senders MUST NOT use a cached document that is older than **24 hours**,
  whatever lifetime the receiver sent; they refetch first.
- The cache lifetime is independent of the pin lifetime: the pin outlives the
  cached document and is refreshed by the next successful fetch.

## 5. Fetch failures and invalid documents

A sender that has no usable cached document fetches one before delivering.

- The fetch fails (connection, TLS), the answer is not `200`, the body is not
  a JSON object, `max_message_size` is missing, or a member defined in §3 has
  the wrong JSON type → the
  sender handles the delivery attempt as **`temporary_failure`**
  (`errors.md` §2). This is fallback-eligible (`errors.md` §3). No pin is set
  or refreshed.
- Exception: a `404` problem of type `unsupported_version` is handled as
  `unsupported_version`. Its `versions` member tells the sender which
  capabilities document to fetch instead, if any (`discovery.md` §5.1).
- Members with values outside the ranges of §3 (e.g. `max_message_size` below
  the floor) are **used as advertised**. Senders do not police receivers;
  range violations are a conformance-test matter. The clamp of
  `discovery_pin_max_age` to one year (`discovery.md` §3.1) still applies.
