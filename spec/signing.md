# IDMX Signing

Status: **draft**. Baseline: `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17) plus the
profile decisions of 2026-09-17 recorded here.
License: CC-BY-4.0 (see `LICENSE`).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
BCP 14 (RFC 2119, RFC 8174).

## 1. Overview

Every `POST /v1/messages` request is authenticated with an **HTTP Message
Signature (RFC 9421)** made by the sending domain. Authentication is mandatory
in v1; a receiver MUST reject unsigned or unverifiable requests with
`invalid_signature` and the sender MUST NOT fall back to SMTP on that error.

`GET /v1/capabilities` is unsigned.

Responses are not signed in v1; TLS 1.3 authenticates the receiver.

## 2. RFC 9421 profile

### 2.1 Algorithm

- The only algorithm in v1 is **`ed25519`** (RFC 9421 §3.3.6, RFC 8032).
- No negotiation. A receiver MUST reject any other `alg` value or key type.

### 2.2 Body digest

- The request MUST carry `Content-Digest` (RFC 9530) with exactly one
  **`sha-256`** entry.
- The digest is computed over the **exact bytes of the HTTP content** as sent.
  There is **no canonicalization**: the body is opaque, and the embedded
  RFC 5322/MIME message is carried byte-for-byte.
- The receiver MUST recompute the digest over the received content and reject
  a mismatch with `invalid_signature`. Digest algorithms other than `sha-256`
  are ignored.

### 2.3 Covered components

The signature MUST cover, in this order:

```text
"@method"
"@authority"
"@path"
"content-digest"
"content-type"
"content-length"
"idempotency-key"
```

The envelope (`from`, `to`) and the message are covered through
`content-digest`.

A receiver MUST reject a signature that omits any of these components. It MAY
accept additional covered components.

### 2.4 Signature parameters

| Parameter | Requirement |
|---|---|
| `created` | REQUIRED. Seconds since the epoch at signing time. See §3. |
| `keyid` | REQUIRED. DNS name of the key record, lower case, no trailing dot: `<selector>._idmxkey.<domain>`. See §4. |
| `alg` | REQUIRED. Literal `"ed25519"`. |
| `tag` | REQUIRED. Literal `"idmx-v1"`. Signatures with another tag are ignored. |
| `expires`, `nonce` | MUST NOT be sent in v1; receivers ignore them. |

- The signature label is `idmx`.
- A request MUST contain exactly one signature with `tag="idmx-v1"`. Other
  signatures (e.g. added by intermediaries) are ignored.

Example (line-wrapped for display):

```http
POST /v1/messages HTTP/1.1
Host: idmx.receiver.example
Content-Type: multipart/mixed; boundary=idmx
Content-Length: 1834
Idempotency-Key: 01J8ZQ4M9X6T3V5B7N2K0HCDEF
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: idmx=("@method" "@authority" "@path" "content-digest"
    "content-type" "content-length" "idempotency-key");created=1789668000;
    keyid="s1._idmxkey.sender.example";alg="ed25519";tag="idmx-v1"
Signature: idmx=:<base64 64-byte signature>:
```

### 2.5 Domain binding

- The **signing domain** is the `<domain>` part of `keyid`.
- The domain of the envelope `from` address MUST equal the signing domain
  (case-insensitive, after IDNA A-label conversion). Otherwise →
  `invalid_signature`.
- `@authority` binds the request to the receiver's IDMX host, so a captured
  request cannot be replayed to a different receiver. For this to hold, a
  receiver MUST reject (`invalid_signature`) any request whose authority is not
  one it serves, instead of accepting whatever `Host` / `:authority` the client
  sent.

- The match is **exact**. A key under `example.org` does not authorize
  `sub.example.org`; there is no organizational-domain or public-suffix logic.
  A subdomain publishes its own `_idmxkey` records (a CNAME to the parent's
  record is sufficient).

## 3. Timestamp and replay

- Receivers MUST reject a signature whose `created` differs from their clock
  by more than **5 minutes** in either direction (`invalid_signature`).
- Retries MUST **re-sign with a fresh `created`** and MUST reuse the **same
  `Idempotency-Key`**.
- Receivers remember idempotency keys for at least the maximum sender retry
  window (7 days, `delivery.md` §4) and return the original result for duplicates. Within
  the ±5 min window a replayed request is therefore harmless: it yields the
  stored result and no second delivery.

## 4. Key discovery

### 4.1 Record

Public keys are published as a DKIM-style **TXT record** at
`<selector>._idmxkey.<domain>`:

```dns
s1._idmxkey.sender.example. TXT "v=IDMX1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
```

| Tag | Requirement |
|---|---|
| `v` | REQUIRED, MUST be first. Literal `IDMX1`. |
| `k` | REQUIRED. Literal `ed25519`. |
| `p` | REQUIRED. Base64 (RFC 4648 §4, padded) of the raw 32-byte Ed25519 public key. Empty value = key revoked. |

- Tag-list syntax follows DKIM (RFC 6376 §3.2). Unknown tags MUST be ignored.
- A name MUST resolve to exactly one IDMX key record; zero or several →
  verification fails.
- `<selector>` is one or more DNS labels.

### 4.2 Lookup failures

- NXDOMAIN, no record, malformed record, or empty `p=` → `invalid_signature`
  (permanent).
- DNS timeout / SERVFAIL → `temporary_failure` (sender retries).

### 4.3 Caching

Receivers cache key records per DNS TTL. DNSSEC is honored when present.

- A key record MUST NOT be cached longer than its DNS TTL, and never longer
  than **1 hour**, so that a revocation takes effect within an hour regardless
  of TTL mistakes.
- A negative result (NXDOMAIN, no record) MUST NOT be cached longer than
  **5 minutes**, so that a newly published selector becomes usable quickly.

### 4.4 Rotation and revocation

- **Rotation:** publish a new selector, start signing with it, keep the old
  record until in-flight requests have drained (≥ 5 min skew window plus DNS
  TTL), then remove it.
- **Revocation:** set `p=` to empty (or remove the record). Takes effect as
  caches expire; operators SHOULD use short TTLs on key records.

## 5. Delegated sending

- A domain delegates to a provider with a **selector CNAME** to a
  provider-hosted key record; one selector per provider:

```dns
prov1._idmxkey.sender.example. CNAME sender-example.keys.provider.example.
```

- `keyid` always names the record **under the sending domain**, never the
  CNAME target. The signing domain stays the customer's domain.
- Providers rotate keys freely behind the CNAME.

## 6. Forwarding: two-layer signatures

- Transport signature = the **current hop's domain**.
- Message-level DKIM inside the MIME body = the **original author**.
- Alias expansion and list explosion re-originate as new deliveries signed by
  the forwarding domain (v1: receiver-internal, spec otherwise silent).

TODO: envelope `from` on forwarded mail (forwarder's address vs SRS-style
rewrite) — follows from §2.5 but needs explicit text.

## 7. Verification procedure

A receiver processes a request in this order:

1. Select the single signature with `tag="idmx-v1"`; check `alg`, required
   parameters, and covered components (§2.3, §2.4).
2. Check `created` against the ±5 min window (§3).
3. Recompute and compare `Content-Digest` (§2.2).
4. Fetch the key named by `keyid` (§4).
5. Verify the Ed25519 signature over the RFC 9421 signature base.
6. Check the envelope `from` domain against the signing domain (§2.5).

Any failure except a temporary DNS error → `invalid_signature`.

## 8. Receiver trace headers

Before handing an accepted message to local delivery, the receiver prepends
two header fields to the message. Only verified requests are delivered, so the
result is always `pass`.

```text
Received: from sender.example by idmx.receiver.example with IDMX
    id 01J8ZQ4M9X6T3V5B7N2K0HCDEF; Thu, 17 Sep 2026 20:00:01 +0000
Authentication-Results: idmx.receiver.example;
    idmx=pass header.d=sender.example header.s=s1
```

### 8.1 `Received`

RFC 5321 §4.4 syntax with:

| Clause | Value |
|---|---|
| `from` | The signing domain. The client IP address MAY follow as a comment. |
| `by` | The receiver's host name. |
| `with` | The literal protocol keyword `IDMX`. |
| `id` | The `Idempotency-Key` of the delivery. |
| `for` | OPTIONAL, and only if the delivery had exactly one recipient. |

### 8.2 `Authentication-Results`

RFC 8601 syntax with the method **`idmx`**:

- `header.d` = signing domain, `header.s` = selector of the `keyid`.
- The authserv-id is the receiver's host name. As RFC 8601 §5 requires, the
  receiver MUST remove pre-existing `Authentication-Results` fields that carry
  its own authserv-id.
- Results of message-level checks (e.g. `dkim=` for the author's DKIM
  signature inside the message) MAY be added as usual; they are independent of
  `idmx=`.

TODO: IANA registrations (`with` protocol type `IDMX`, authentication method
`idmx`); revisit whether `header.` is the right RFC 8601 property type for
values taken from the HTTP signature rather than a message header.

## 9. Test vectors

See `test-vectors/`. `signing-basic.json` holds a complete valid request:
inputs, key pair, and the expected `Content-Digest`, `Signature-Input`,
signature base, and `Signature`. Ed25519 is deterministic, so signers must
reproduce the expected values byte for byte.

TODO: negative vectors (expired `created`, wrong digest, revoked key) as data
rather than implementation tests.
