# IDMX IANA Considerations

Status: **draft**. These are the registrations IDMX would request. None is filed
until the specification is on a standards track; until then the names below are
used unregistered.
License: CC-BY-4.0 (see `LICENSE`).

## 1. Underscored DNS node names

"Underscored and Globally Scoped DNS Node Names" registry (RFC 8552):

| RR Type | `_NODE NAME` | Reference |
|---|---|---|
| SVCB | `_idmx` | `discovery.md` §2 |
| TXT | `_idmxkey` | `signing.md` §4.1 |

## 2. Mail transmission type

"Mail Transmission Types" registry (RFC 3848), used in the `with` clause of
`Received` (`signing.md` §8.1):

| Keyword | Description | Reference |
|---|---|---|
| `IDMX` | Delivery over IDMX (HTTPS with an RFC 9421 domain signature) | `signing.md` §8.1 |

## 3. Email authentication method

"Email Authentication Methods" registry (RFC 8601 §6.2):

| Method | Version | ptype | Property | Value | Status | Reference |
|---|---|---|---|---|---|---|
| `idmx` | 1 | `header` | `d` | Signing domain (`keyid` domain) | active | `signing.md` §8.2 |
| `idmx` | 1 | `header` | `s` | Selector of the `keyid` | active | `signing.md` §8.2 |

"Email Authentication Result Names" registry (RFC 8601 §6.3): add `idmx` to the
methods of the existing result `pass`. Receivers only deliver verified requests,
so no other result is produced.

## 4. No other registrations

- HTTP field names: IDMX uses `Content-Digest`, `Signature-Input`, `Signature`
  (RFC 9530, RFC 9421) and `Idempotency-Key` as defined elsewhere; it defines no
  new field.
- Problem `type` URIs live under `https://idmx-project.org/` and need no
  registry.
- Media types: none new; the body is `multipart/mixed`.
