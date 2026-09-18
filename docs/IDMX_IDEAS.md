# IDMX Project — Ideas and Design Notes

> **IDMX — Inter-Domain Mail Exchange** (formerly working name "OMDA")
>
> This document collects early ideas for a modern mail delivery mechanism that preserves existing email addresses and remains backwards-compatible with SMTP.

## Motivation

Email has remained difficult to replace because it provides several valuable properties at once:

- global `user@domain` addressing
- decentralized operation
- cross-organization interoperability
- asynchronous delivery
- provider independence
- compatibility across different clients and servers
- domain-controlled identity and routing

Many modern communication tools improve the user experience inside their own ecosystems, but they usually lose one or more of these properties.

The goal of IDMX is therefore **not to replace email identities**.

Instead, the idea is to preserve:

```text
alice@example.com
```

while allowing modern mail servers to communicate using an HTTPS-based API when both sides support it.

SMTP remains available as a compatibility fallback.

---

## Core Idea

Treat an email address as an **identifier**, not as something inherently tied to SMTP.

For example:

```text
alice@example.com → bob@example.org
```

could be delivered like this:

```text
Sender
  │
  ├─ discover whether example.org supports IDMX
  │
  ├─ yes → deliver through HTTPS
  │
  └─ no  → fall back to SMTP
```

This permits gradual migration without requiring:

- new user identities
- new address formats
- a coordinated migration date
- every mail provider to upgrade at once

A possible long-term deployment model:

```text
new → new       IDMX / HTTPS
new → old       SMTP fallback
old → new       SMTP
old → old       SMTP
```

Users continue to use normal email addresses regardless of the transport used underneath.

---

## Why an API Instead of a New Custom Protocol?

The idea is to avoid inventing an entirely new wire protocol where possible.

IDMX could instead define its server-to-server interface using an **OpenAPI specification** over existing technologies:

- HTTPS
- HTTP/2 or HTTP/3
- JSON
- TLS
- DNS
- existing cryptographic primitives

This would make independent implementations easier to build.

A developer could create an IDMX-compatible server in almost any modern language by implementing the published API contract.

Examples:

- Go
- Rust
- Python
- Java
- .NET
- Node.js
- PHP

The standard would describe more than just HTTP endpoints, however. It would also need to define discovery, authentication, retries, error semantics, versioning, and SMTP compatibility behavior.

---

## Discovery

A sender needs a reliable way to determine whether the recipient's domain supports IDMX.

For:

```text
bob@example.org
```

the sender first extracts:

```text
example.org
```

and performs IDMX capability discovery.

### Preferred Direction: DNS-Based Discovery

DNS is a natural place for this because email already uses DNS for MX routing.

Conceptually:

```text
bob@example.org
       │
       ▼
 example.org
       │
       ├─ IDMX discovery record exists
       │        │
       │        ▼
       │   HTTPS endpoint
       │
       └─ no IDMX record
                │
                ▼
             MX lookup
                │
                ▼
               SMTP
```

A hosted mail provider could therefore advertise an endpoint independently of the web server used by the domain.

Example concept:

```dns
example.org.              MX   10 mx.provider.example.
_idmx.example.org.        SVCB 1 idmx.provider.example.
```

The exact DNS format is still an open design question.

Potential mechanisms include:

- SVCB / HTTPS-style service discovery
- a dedicated DNS record if one were ever standardized
- TXT records during experimentation
- a `/.well-known/` discovery endpoint as a secondary mechanism

### Why Not Only `/.well-known/`?

A simple design could attempt:

```text
https://example.org/.well-known/idmx
```

but the website at `example.org` may be unrelated to the domain's mail infrastructure.

For example:

```text
example.org
    website → unrelated hosting provider

MX
    → Microsoft / Google / Fastmail / self-hosted server
```

DNS-based service discovery handles this separation more cleanly.

---

## Example Delivery Flow

For:

```text
alice@sender.example
        ↓
bob@receiver.example
```

the sender could perform:

```text
1. Extract receiver.example
2. Query IDMX discovery information
3. If supported:
      sign request
      POST message via HTTPS
4. If unsupported:
      use normal MX lookup + SMTP
5. Apply retry / failure rules based on response semantics
```

Possible endpoint:

```http
POST /v1/messages
Content-Type: application/json
```

Possible request:

```json
{
  "from": "alice@sender.example",
  "to": ["bob@receiver.example"],
  "subject": "Hello",
  "body": {
    "text": "Hello Bob"
  }
}
```

The final message representation is still an open question.

Possible strategies include:

- structured JSON messages
- transporting RFC 5322 / MIME messages inside the API
- a hybrid model where the envelope is structured but the message body remains RFC-compatible

The hybrid approach may make migration easier.

---

## Error Semantics

Fallback behavior must be carefully specified.

An HTTPS failure must not automatically mean:

> Try SMTP.

Otherwise SMTP could bypass a deliberate IDMX rejection.

For example:

```http
404 Recipient Not Found
```

should probably be treated as a permanent delivery failure, not as permission to try SMTP.

Potential classes:

```text
2xx
    delivery accepted

4xx request/authentication errors
    usually permanent from this sender request

5xx temporary service failures
    retry according to policy
```

More specific IDMX error identifiers would likely be necessary.

Examples:

```text
recipient_not_found
invalid_signature
unsupported_version
unsupported_feature
temporary_failure
rate_limited
message_too_large
```

The standard should explicitly specify which failures:

- may be retried
- may fall back to SMTP
- must never fall back to SMTP

---

## SMTP Fallback

SMTP compatibility is central to the proposal.

A modern sender should be able to deliver through IDMX when available while continuing to reach every existing mail domain.

Conceptually:

```text
                    DNS
                     │
                     ▼
Sender application
        │
        ▼
┌───────────────────────┐
│ Delivery service      │
│                       │
│ IDMX discovery        │
│ authentication        │
│ retry logic           │
└─────────┬─────────────┘
          │
     ┌────┴────┐
     │         │
     ▼         ▼
   HTTPS      SMTP
   IDMX       fallback
```

A reference implementation does not need to implement SMTP itself.

It could hand fallback delivery to an existing MTA such as:

- Postfix
- Exim
- OpenSMTPD

This avoids reimplementing decades of SMTP behavior.

---

## Authentication and Sender Verification

A major design goal should be to avoid repeating SMTP's historical lack of strong sender authentication.

Modern email relies on layers such as:

- SPF
- DKIM
- DMARC

IDMX should make authenticated domain-to-domain delivery a first-class property from version 1.

A request could include a cryptographic signature covering values such as:

```text
sender domain
recipient
timestamp
message hash
unique message ID
request metadata
```

The receiver could retrieve the sending domain's public key through a defined discovery mechanism and verify that the sending domain authorized the delivery.

Important areas to define:

- signing algorithm
- key discovery
- key rotation
- canonicalization
- timestamp tolerance
- nonce or message ID handling
- replay protection
- domain identity
- delegated providers
- multiple sending servers
- revocation behavior

The exact mechanism should reuse existing standards where possible instead of inventing custom cryptography.

---

## Idempotency

Retries are unavoidable in mail delivery.

The API therefore needs idempotency semantics from the beginning.

A sender should be able to retry the same delivery without causing multiple copies to appear.

Possible mechanisms:

```text
message ID
delivery ID
idempotency key
```

Example:

```http
Idempotency-Key: 01J...
```

The receiving server should recognize repeated attempts for the same delivery.

---

## Queueing and Retries

Like SMTP, IDMX delivery must survive temporary failures.

A sending implementation needs:

- durable queues
- exponential backoff
- delivery attempt history
- retry limits
- temporary vs permanent failure handling
- per-domain throttling
- duplicate protection

The HTTP request itself should not be responsible for long-running delivery behavior.

A practical implementation would use a separate delivery worker.

---

## Capabilities

IDMX could support capability negotiation.

Possible capabilities may eventually include:

```text
attachments
delivery receipts
structured threading
encryption metadata
message size limits
rich content
binary transfer
recipient validation
message status queries
```

Example conceptual endpoint:

```http
GET /v1/capabilities
```

However, the initial version should remain minimal.

A complex capability system too early could slow adoption and interoperability.

---

## Potential Minimal v1

A deliberately small first version might contain:

```text
Identity:
    user@example.com

Discovery:
    DNS-based service discovery

Transport:
    HTTPS

API:
    OpenAPI-defined

Encoding:
    JSON and/or RFC-compatible message payload

Authentication:
    domain-level request signatures

Delivery:
    POST /v1/messages

Idempotency:
    required

Status:
    explicit delivery result semantics

Fallback:
    SMTP
```

The initial purpose would simply be to prove:

```text
alice@domain-a.test
        ↓
IDMX discovery
        ↓
HTTPS delivery
        ↓
bob@domain-b.test
```

and:

```text
alice@domain-a.test
        ↓
no IDMX support
        ↓
SMTP fallback
        ↓
bob@legacy.test
```

---

## Relationship to JMAP

JMAP is relevant because it modernizes much of the **client-to-mail-provider** side of email using HTTPS and JSON.

Conceptually:

```text
mail client
    │
    │ JMAP / HTTPS
    ▼
mail provider
    │
    │ SMTP
    ▼
remote mail provider
```

IDMX explores the missing server-to-server modernization:

```text
mail client
    │
    │ JMAP or other client API
    ▼
mail provider
    │
    │ IDMX / HTTPS
    ▼
remote mail provider
```

with SMTP remaining available when the recipient does not support IDMX.

IDMX should not attempt to replace JMAP, IMAP, or mailbox APIs.

Its intended scope is primarily **inter-domain delivery**.

---

## Software Components

The project could eventually contain several distinct components.

### `idmx-spec`

Canonical specification.

Contains:

- OpenAPI document
- discovery rules
- message model
- authentication requirements
- response and error semantics
- retry rules
- SMTP fallback rules
- security considerations
- versioning rules
- examples
- protocol design notes

This should be the project's source of truth.

### `idmx-reference-server`

Reference receiving implementation.

Responsibilities:

- HTTPS API
- OpenAPI validation
- signature verification
- recipient lookup
- rate limiting
- idempotency
- message acceptance
- persistence hooks
- response semantics

### `idmx-reference-client`

Reference outbound implementation.

Responsibilities:

- recipient domain extraction
- IDMX discovery
- request creation
- signing
- HTTPS delivery
- retries
- error handling
- SMTP fallback integration

Could expose both a library and CLI.

### `idmx-conformance`

Independent compatibility test suite.

Purpose:

- test third-party implementations
- verify discovery behavior
- verify API compliance
- verify authentication
- test expected error semantics
- test idempotency
- test retry behavior

A future goal could be:

```bash
idmx-conformance https://idmx.example.org
```

### `idmx-devnet`

Local development environment.

Potential components:

```text
modern-domain-a
modern-domain-b
legacy-smtp-domain
broken-domain
DNS server
PostgreSQL
Postfix
IDMX sender
IDMX receiver
```

Docker Compose would be suitable initially.

### Components That Can Wait

These can remain packages inside the reference implementations until there is a clear reason to split them:

- `idmx-discovery`
- `idmx-auth`
- `idmx-smtp-bridge`
- language SDK repositories
- documentation website

Avoid creating many empty repositories before the specification stabilizes.

---

## Initial Repository Layout

A single monorepo, `github.com/idmx-project/idmx`. Splitting into separate repositories (spec, conformance, devnet) can wait until the specification stabilizes.

```text
idmx/
    spec/            openapi.yaml, discovery.md, signing.md, errors.md (prose CC-BY-4.0)
    crates/
        idmx-core/     envelope types, RFC 9421 sign/verify, SVCB discovery
        idmx-server/   receiver daemon (binary: idmxd)
        idmx-client/   sender library + CLI (binary: idmx)
    devnet/          Docker Compose environment (CoreDNS, Postfix, 2 modern domains, 1 legacy)
    docs/            design notes (this document)
```

Code and `spec/openapi.yaml` are `MIT OR Apache-2.0`; specification prose is CC-BY-4.0.

Dependency direction:

```text
                   spec/
                     │  (normative; code follows)
                     ▼
                 idmx-core
                 /       \
                ▼         ▼
         idmx-client   idmx-server
                \         /
                 ▼       ▼
                  devnet/
```

A conformance suite (`idmx-conformance`) comes later, depending only on `spec/`.

The specification must remain implementation-independent.

---

## Suggested Development Stack

For an initial prototype:

```text
Backend:
    Rust

API definition:
    OpenAPI 3.1

Database:
    PostgreSQL

Queue:
    PostgreSQL initially

DNS:
    CoreDNS or dnsmasq for local development

SMTP compatibility:
    Postfix

TLS:
    application TLS, Caddy, or nginx

Development:
    Docker Compose
```

A dedicated queue product such as Redis, RabbitMQ, NATS, or Kafka is unnecessary for the first prototype.

---

## Development Test Domains

The development environment should simulate different recipient capabilities.

For example:

```text
modern.test
    IDMX supported

legacy.test
    SMTP only

broken.test
    advertises IDMX but intentionally fails

invalid.test
    malformed discovery information
```

Important integration tests:

```text
modern → modern
    IDMX succeeds

modern → legacy
    SMTP fallback succeeds

modern → broken
    correct retry/failure behavior

unknown recipient
    permanent rejection

duplicate delivery
    stored once

invalid signature
    rejected without SMTP bypass

temporary outage
    queued and retried

unsupported version
    negotiated or rejected correctly
```

---

## Naming

The project name is:

# IDMX — Inter-Domain Mail Exchange

"Domain" means the DNS domain after the `@`. The domain is the unit of identity (signing keys), routing (discovery record), and policy (reputation, rate limits, pinning). The protocol covers exactly the hop between two independently administered domains; everything intra-domain (client access, alias expansion, mailbox storage) is out of scope. The "MX" deliberately echoes the DNS MX record.

Naming conventions:

```text
Protocol:       IDMX
Effort (prose): The IDMX Project
GitHub org:     idmx-project   (bare `idmx` is taken by a personal account)
Crates:         idmx, idmx-core, idmx-server, idmx-client
Binaries:       idmxd (receiver daemon), idmx (CLI)
DNS labels:     _idmx.<domain>, <selector>._idmxkey.<domain>
Domain:         idmx.org preferred
```

Rejected names:

- **OMDA — Open Mail Delivery API** (original working name): "Open" is redundant for a public standard, and "API" undersells a spec that also covers discovery, signing, and fallback.
- **IMD — Interdomain Mail Delivery**: precise but bland; IDMX keeps the precision and adds the MX echo.
- **FMX — Federated Mail Exchange**: "federated" now implies ActivityPub/Matrix, plus government connotations.
- **MDX — Mail Delivery Exchange**: collides with MDX (Markdown + JSX).
- **MoH — Mail over HTTPS**: ties the name to the transport; usable as a tagline ("IDMX: mail over HTTPS").

Known unrelated uses of "IDMX" (checked 2026-09-17): iDMX stage-lighting products (DMX512), McKinsol iDMX (SAP master data software, owns idmx.io), EndurID IDMx (healthcare), the Mexican Digital Identity Association, and the similarly named IPMX AV standard. None are in the mail or Internet-standards space. A trademark lookup for McKinsol's "iDMX" is advisable before going public.

---

## Design Principles

IDMX should aim to follow these principles:

1. **Preserve existing email addresses.**

   `user@domain` remains the universal identity and routing model.

2. **Allow incremental deployment.**

   A domain should gain benefits immediately when communicating with another supporting domain.

3. **Never require a global migration event.**

   SMTP fallback allows old and new infrastructure to coexist.

4. **Reuse existing Internet standards.**

   Prefer HTTPS, DNS, TLS, OpenAPI, and established cryptographic mechanisms.

5. **Do not reinvent mailbox access.**

   IDMX is primarily about inter-domain transport, not replacing IMAP, JMAP, or mail clients.

6. **Build authentication into version 1.**

   Strong sender-domain authentication should not be added years later as an extension.

7. **Make failure semantics explicit.**

   Implementations must agree on retries, permanent failures, and SMTP fallback.

8. **Require idempotency.**

   Network retries must not create duplicate messages.

9. **Keep the first version small.**

   Reliable interoperability matters more than a large feature set.

10. **Keep the specification implementation-independent.**

    The reference implementation demonstrates the standard; it does not define it.

---

## Decisions (2026-09-17)

Working decisions for v1. Each can be revisited, but they are the baseline for the first spec draft and prototype.

| Area | Decision | Rationale |
|---|---|---|
| Payload | **Hybrid**: structured JSON envelope (from, to, IDs, signature metadata) + opaque RFC 5322/MIME body | Lossless SMTP fallback, DKIM survives, MIME already solves attachments |
| Discovery | **SVCB on `_idmx.<domain>`**; no `/.well-known/` fallback, no TXT | Standards-track shape from day one; one code path; mail host independent of web host |
| Downgrade protection | **Cache + pin** positive discovery with a max-age (MTA-STS-style TOFU); honor DNSSEC when present | A stripped DNS answer must not silently permit SMTP downgrade; requiring DNSSEC would kill deployability |
| Sender authentication | **HTTP Message Signatures (RFC 9421)**, public keys in DNS at `<selector>._idmxkey.<domain>` | Reuses existing standards and the DKIM operational model |
| Delegated sending | **DKIM-style selector CNAME** to provider-hosted keys; one selector per provider | Providers rotate keys freely; admins already know the model |
| Forwarding | **Two-layer signatures**: transport signature = current hop's domain; message-level DKIM inside the MIME body = original author | Forwarder signs the hop, original DKIM still proves authorship |
| Replay / idempotency | Signature covers a created timestamp (±5 min skew). Retries re-sign with a fresh timestamp but the **same idempotency key**. Receiver remembers keys for at least the maximum sender retry window (e.g. 7 days) and returns the original result for duplicates | Cheap replay defense without a nonce round trip; retries never duplicate |
| SMTP fallback | If IDMX is advertised but unreachable/5xx: **retry IDMX with backoff for a bounded window (order of 1–4 h), then fall back to SMTP**. Explicit IDMX rejections (4xx-class semantic errors) never fall back | Balances deliverability against trivial forced downgrade |
| Multi-recipient | **One POST per recipient domain, per-recipient result array** in the response; the idempotency key covers the whole delivery | Body sent once; mirrors SMTP RCPT semantics |
| Bounces / DSN | **Maximize synchronous validation before 2xx** (recipient exists, quota, policy). Post-acceptance failures are reported as a classic RFC 3464 DSN delivered as a normal message | No new async mechanism in v1 |
| Encryption | **TLS 1.3 mandatory**. End-to-end encryption stays in the message layer (PGP / S/MIME), untouched by IDMX | Guaranteed hop encryption is already a large win over opportunistic STARTTLS |
| Versioning / capabilities | **Major version in URL path** (`/v1/`), cacheable `GET /v1/capabilities` for versions, limits and operational parameters — **no feature flags, no optional behavior inside a major version** (revised 2026-09-18, `spec/capabilities.md`); unknown JSON fields must be ignored, minor evolution is additive only | No discover-by-failure, no DNS record bloat |
| Size limits | Receiver advertises `max_message_size` in capabilities; spec mandates a **floor (e.g. ≥ 25 MB)**; over limit → `message_too_large` (permanent). No chunked/resumable upload in v1 | Predictable interop, minimal state |
| Inbound architecture | IDMX receiver is a **front door beside the MTA**: hands the accepted MIME message to the same local delivery (LMTP / pipe), adding a trace header and `Authentication-Results`. Mailbox layer is transport-unaware | Consistent with "do not reinvent mailbox access" |
| Aliases / lists / migration | **v1: receiver-internal, spec silent** (notes only). Expansion and list explosion re-originate as new deliveries signed by the forwarding domain. Domain migration = change the SVCB record; pin max-age bounds the transition. **Later version: specify list semantics** (list fields, loop detection, re-signing rules) | Keeps v1 small; two-layer signatures already cover the mechanics |
| Reference implementation | **Rust** | Correctness focus for protocol and signature handling |

### Abuse and Spam — Phased Approach

While SMTP remains a parallel path, any IDMX-only anti-abuse mechanism is bypassable: a spammer simply uses SMTP. Abuse control inside IDMX therefore becomes meaningful only once communication primarily flows IDMX ↔ IDMX. The design is phased accordingly:

**v1 — identity foundation + error hooks**

- mandatory sender-domain authentication, giving receivers a stable, unforgeable domain identity
- `rate_limited` / `policy_rejected` errors with `Retry-After`
- abuse-report contact advertised via discovery/capabilities
- reputation and filtering remain receiver-local policy, as with SMTP today — but built on strong identity (**domain reputation on strong identity**)

**Later — once IDMX ↔ IDMX dominates**

- **first-contact friction**: unknown sender→recipient pairs may be throttled, quarantined, or challenged; known correspondents flow freely
- **optional sender attestations**: provider- or third-party-signed claims in the envelope

Constraint: both must be addable **without changing the basic delivery model**. Revised 2026-09-18: v1 has no feature flags; both are candidates for a later major version, where they would be mandatory. The ignored-unknown-fields rule keeps the envelope extensible for them.

---

## Open Questions

Remaining areas still requiring design work:

- ~~SVCB record parameters~~ — settled 2026-09-17, see `spec/discovery.md`: standard `port` (default 443), fixed path at origin root, no custom SvcParamKeys; h2 mandatory, h3 optional via `alpn`; pin max-age = `discovery_pin_max_age` in the capabilities document
- ~~resolvers lacking SVCB support~~ — settled 2026-09-17: pin-aware; lookup failure without a pin → SMTP, with a valid pin → keep using the pinned endpoint. Settled 2026-09-18: a valid pin does not forbid SMTP fallback after the window (no `enforce` semantics in v1)
- ~~envelope schema and body layout~~ — settled 2026-09-18, see `spec/delivery.md`: `multipart/mixed` with exactly two parts (`application/json` envelope, raw `message/rfc822`); envelope = `from` (mailbox or `null`) + `to`; `Idempotency-Key` = 1–128 chars of `A-Za-z0-9._~-`, scoped per signing domain, reuse with other content → `idempotency_conflict`. Still open: local-part syntax
- ~~RFC 9421 profile~~ — settled 2026-09-17, see `spec/signing.md`: Ed25519 only; covers `@method`, `@authority`, `@path`, `content-digest`, `content-type`, `content-length`, `idempotency-key`; `sha-256` digest over raw bytes, no canonicalization
- ~~key record format~~ — settled 2026-09-17: DKIM-style TXT `v=IDMX1; k=ed25519; p=<base64>`; empty `p=` revokes. Still open: key cache bounds, subdomain signing policy
- ~~exact retry schedule and fallback window value~~ — settled 2026-09-18, see `spec/errors.md` §3.1: backoff 1 min doubling to 1 h cap, ±20 % jitter, `Retry-After` as lower bound; fallback window 2 h (1–4 h); give-up 5 days. Only connection/TLS failure or request-level 5xx falls back; `rate_limited`, `mailbox_full` and all per-recipient results never do
- ~~pin max-age defaults~~ — settled 2026-09-18: recommended 7 days, senders clamp at 1 year. Still open: pin-failure reporting (TLS-RPT equivalent?)
- ~~trace / `Authentication-Results` header format~~ — settled 2026-09-18, see `spec/signing.md` §8: `Received: … with IDMX id <idempotency-key>` plus `Authentication-Results: …; idmx=pass header.d=… header.s=…`. Still open: IANA registrations
- settled 2026-09-18 (constants): size floor 25 MiB with no upper limit; idempotency retention and sender retry cap 7 days; signing domain must match exactly (no subdomain inheritance); key cache ≤ DNS TTL ≤ 1 h, negative ≤ 5 min
- ~~per-recipient result schema~~ — settled 2026-09-18: request-level failures → 4xx/5xx problem; otherwise always `200` with `accepted` / `rejected` / `deferred` per recipient; deferred recipients are retried as a new delivery with a new key. Retry schedule for deferred recipients = `spec/errors.md` §3.1; deferred never falls back to SMTP
- ~~capabilities document schema~~ — settled 2026-09-18, see `spec/capabilities.md`: members are `versions`, `max_message_size` (required), `max_recipients`, `discovery_pin_max_age`, `abuse_contact`; **no `features`, no optional behavior in v1** — new behavior = new major version, mandatory there; `unsupported_feature` dropped. Caching: SHOULD `max-age=3600`, default 1 h, never older than 24 h. Unfetchable/invalid document → `temporary_failure` (fallback-eligible, no pin); out-of-range values used as advertised
- ~~abuse-report contact format~~ — settled 2026-09-18: `abuse_contact` = one `mailto:` URI
- list semantics (post-v1)
- ~~major version negotiation~~ — settled 2026-09-18, see `spec/discovery.md` §5: capabilities lists all served majors in `versions` (absent = `["v1"]`), sender uses the highest common one, no path probing; no common version → SMTP fallback allowed immediately, even while pinned. Deprecation settled 2026-09-18, `spec/discovery.md` §5.1–5.2: receivers MUST serve N-1 for 24 months after vN is final, senders SHOULD; every `unsupported_version` problem carries `versions`, so first contact with a retired version needs no probing
- trademark check for "IDMX"; registration of idmx.org
- E2EE key discovery (post-v1), see spec/delivery.md §7.4

---

## First Milestone

The first milestone should avoid trying to build a complete mail ecosystem.

A successful prototype only needs to demonstrate two flows.

### IDMX Delivery

```text
alice@domain-a.test
        │
        ▼
discover domain-b.test
        │
        ▼
IDMX supported
        │
        ▼
authenticated HTTPS request
        │
        ▼
bob@domain-b.test
```

### Legacy Delivery

```text
alice@domain-a.test
        │
        ▼
discover legacy.test
        │
        ▼
IDMX unavailable
        │
        ▼
SMTP fallback
        │
        ▼
bob@legacy.test
```

If these flows work reliably, the core architectural idea has been demonstrated.

---

## Short Project Description

Description for repositories:

> **IDMX (Inter-Domain Mail Exchange) is an experimental standards project for modern HTTPS-based inter-domain mail delivery while preserving existing `user@domain` addresses and SMTP compatibility.**
