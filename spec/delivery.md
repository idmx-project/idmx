# IDMX Delivery

Status: **draft**. Baseline: `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17) plus the
delivery decisions of 2026-09-18 recorded here.
License: CC-BY-4.0 (see `LICENSE`).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
BCP 14 (RFC 2119, RFC 8174).

## 1. Overview

A delivery is one `POST /v1/messages` to the endpoint discovered for the
recipient domain (`discovery.md`), signed by the sending domain (`signing.md`).

- **One POST per recipient domain.** The message is sent once; the response
  carries one result per recipient.
- The payload is **hybrid**: a structured JSON envelope plus the opaque
  RFC 5322/MIME message, byte-for-byte. DKIM signatures inside the message
  survive, and SMTP fallback is lossless.

## 2. Request body

`Content-Type: multipart/mixed; boundary=<boundary>` (RFC 2046) with **exactly
two parts, in this order**:

| # | Part `Content-Type` | Content |
|---|---|---|
| 1 | `application/json` | The envelope (§3), UTF-8 |
| 2 | `message/rfc822` | The message, raw bytes |

- Parts carry no `Content-Transfer-Encoding`; content is binary (8-bit clean).
  The message MUST NOT be base64- or otherwise re-encoded.
- Part headers other than `Content-Type` MUST be ignored.
- Preamble and epilogue SHOULD be empty and MUST be ignored.
- The sender chooses a boundary (RFC 2046: 1–70 characters) that does not occur
  in either part.
- `Content-Length` is REQUIRED (it is a covered signature component). Chunked
  or resumable upload is not part of v1.
- A body that does not match this layout → `invalid_request`.

```http
POST /v1/messages HTTP/2
content-type: multipart/mixed; boundary=idmx-boundary
content-length: 352
idempotency-key: 01J8ZQ4M9X6T3V5B7N2K0HCDEF
content-digest: sha-256=:...:
signature-input: idmx=(...);created=...;keyid="s1._idmxkey.sender.example";alg="ed25519";tag="idmx-v1"
signature: idmx=:...:

--idmx-boundary
Content-Type: application/json

{"from":"alice@sender.example","to":["bob@receiver.example"]}
--idmx-boundary
Content-Type: message/rfc822

From: Alice <alice@sender.example>
...
--idmx-boundary--
```

See `test-vectors/signing-basic.body` for an exact byte sequence.

## 3. Envelope

```json
{ "from": "alice@sender.example", "to": ["bob@receiver.example"] }
```

| Field | Requirement |
|---|---|
| `from` | REQUIRED. Envelope sender (reverse-path): a mailbox (§3.1), or `null` for the null reverse-path used by DSNs. |
| `to` | REQUIRED. 1 to `max_recipients` mailboxes, no duplicates, **all in the same domain**. |

- Unknown fields MUST be ignored. This is the extension point for later
  capabilities (e.g. sender attestations).
- If `from` is a mailbox, its domain MUST equal the signing domain
  (`signing.md` §2.5). If `from` is `null`, the signing domain alone identifies
  the sender.
- The receiver MUST be responsible for the domain of `to`; otherwise →
  `policy_rejected` at request level.
- The envelope has no message identifier: duplicate suppression is the job of
  `Idempotency-Key` (§4); the RFC 5322 `Message-ID` lives in the message.

### 3.1 Mailbox

`<local-part>@<domain>`, split at the **last** `@`.

- `<domain>`: host-name syntax, IDNA A-labels, compared case-insensitively.
- `<local-part>`: 1–64 octets of UTF-8 without control characters; opaque to
  the sender and interpreted only by the receiving domain.

TODO: tighten local-part syntax (RFC 5321 / RFC 6531 alignment, quoting).

## 4. Idempotency

- `Idempotency-Key` is REQUIRED: **1–128 characters of `A-Z a-z 0-9 . _ ~ -`**,
  chosen by the sender, opaque to the receiver. It SHOULD carry at least 128
  bits of entropy (UUID and ULID both fit).
- The key covers the whole delivery (all recipients) and is covered by the
  signature.
- Receivers scope keys **per signing domain** and MUST remember each key and
  its response for **at least 7 days** after first seeing the key.
- Senders MUST NOT retry a request under the same key for longer than 7 days
  after the first attempt; after that they give up and bounce.
- Same key, same `Content-Digest` → the receiver MUST return the **original
  response** (status and body) and MUST NOT deliver again.
- Same key, different `Content-Digest` → `idempotency_conflict` (permanent).
- A key is recorded when the receiver produces a **`200` response**. Request-level
  failures are not recorded: temporary ones must stay retryable under the same
  key, and permanent ones are reproduced by evaluating the request again.
- While a request is being processed, a concurrent request with the same key
  is answered with `temporary_failure`; its retry then receives the recorded
  response.
- Retries of the *same* request re-sign with a fresh `created` and reuse the key
  (`signing.md` §3).

## 5. Response

### 5.1 Request-level failure

If the request as a whole cannot be processed — bad signature, malformed body,
too large, rate limited, service down — the receiver answers **4xx/5xx with an
RFC 9457 problem document** and delivers to nobody. Status codes and retry
semantics: `errors.md` §2.

### 5.2 Per-recipient results

Otherwise the receiver answers **`200 OK`**, always, with one result per
envelope recipient, **in the order of `to`**:

```json
{
  "results": [
    { "recipient": "bob@receiver.example", "status": "accepted" },
    { "recipient": "nobody@receiver.example", "status": "rejected",
      "problem": { "type": "https://idmx-project.org/problems/recipient_not_found" } },
    { "recipient": "carol@receiver.example", "status": "deferred",
      "problem": { "type": "https://idmx-project.org/problems/mailbox_full" },
      "retry_after": 3600 }
  ]
}
```

| `status` | Meaning | Sender action |
|---|---|---|
| `accepted` | Receiver took responsibility for this recipient. | Done. |
| `rejected` | Permanent failure. `problem` REQUIRED. | Bounce to the author. MUST NOT retry, MUST NOT fall back to SMTP. |
| `deferred` | Temporary failure. `problem` REQUIRED; `retry_after` (seconds) OPTIONAL. | Retry later (§5.3). |

- A 200 response with every recipient `rejected` is valid.
- The receiver SHOULD validate as much as possible before answering
  (recipient exists, quota, policy). Failures after `accepted` are reported as
  an RFC 3464 DSN delivered as a normal message.
- Unknown fields and unknown `status` values: senders MUST ignore unknown
  fields and MUST treat an unknown `status` as `deferred`.

### 5.3 Retrying deferred recipients

A retry for deferred recipients is a **new delivery**: a new `Idempotency-Key`
and an envelope whose `to` lists only the deferred recipients. (Reusing the key
would replay the original response.)

Deferred recipients follow the retry schedule of `errors.md` §3.1 (backoff,
`retry_after` as lower bound, give-up after 5 days counted from the first
attempt of the original delivery). `deferred` recipients **never fall back to
SMTP**; at give-up they bounce.

## 6. Capabilities used by delivery

From `GET /v1/capabilities`:

| Field | Meaning |
|---|---|
| `max_message_size` | Largest accepted request body in bytes. REQUIRED. MUST be ≥ **26 214 400** (25 MiB); there is **no upper limit**. Over limit → `message_too_large`. |
| `max_recipients` | Largest accepted `to` length. Absent = 100. MUST be ≥ 100. Over limit → `invalid_request`. |

## 7. Future extensions (informative)

Nothing in this section is part of v1. It records the design room that v1
deliberately leaves, so that later work does not have to break the delivery
model.

### 7.1 How extensions arrive

- As **feature flags** in the `features` object of `GET /v1/capabilities`. A
  sender that does not know a flag ignores it; a receiver that does not offer a
  feature never advertises it. No discover-by-failure.
- As **new envelope or result fields**, which v1 implementations ignore.
- Anything that cannot be expressed this way needs a new major version
  (`/v2/`), selected through the capabilities `versions` list
  (`discovery.md` §5).

### 7.2 Large messages

`max_message_size` has a floor (25 MiB), not a cap: a receiver may already
advertise far more. The floor guarantees that any two conforming systems can
exchange ordinary mail; it cannot be "unlimited", because a mandatory minimum
binds every receiver, however small. The limit counts the whole request body:
v1 cannot treat text and attachments differently, since the message is opaque. Where the receiver *stores* an accepted message
(file system, database, S3-compatible object store) is receiver-internal and
invisible on the wire.

The intended direction for large files is therefore: **the message stays
small, files travel by reference and are effectively unbounded.** What v1 lacks
is that transfer mechanism. Candidates:

- **Resumable upload**: the sender uploads the body in ranges to an upload
  resource, then sends a small delivery request that references it (cf. the
  IETF "Resumable Uploads for HTTP" work).
- **Receiver-hosted external body**: the receiver hands out an upload slot
  (e.g. a pre-signed object-store URL); the sender uploads there and the
  delivery request carries a reference with size and SHA-256 digest inside the
  signed body, so integrity and sender authentication are preserved.

Constraints for either design:

- The upload location MUST be controlled by the **receiver**. A sender-hosted
  URL that the receiver fetches is rejected as a design: SSRF and tracking
  risk, content mutable after signing, and link rot.
- SMTP fallback must stay well-defined: a message too large for the fallback
  path needs a specified outcome (e.g. bounce), never silent loss.

### 7.3 Abuse controls

First-contact friction and sender attestations (`docs/IDMX_IDEAS.md`, "Abuse
and Spam") are expected to arrive as feature flags plus optional envelope
fields.
