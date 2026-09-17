# IDMX Discovery

Status: **draft**. Baseline: `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17) plus the
discovery decisions of 2026-09-17 recorded here.
License: CC-BY-4.0 (see `LICENSE`).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
BCP 14 (RFC 2119, RFC 8174).

## 1. Overview

A sender extracts the recipient domain from `user@domain` (IDNA A-label form)
and looks up IDMX support in DNS. No record and no valid pin → normal MX
lookup and SMTP.

## 2. SVCB record

- Discovery is an **SVCB record (RFC 9460) on `_idmx.<domain>`**.
- No `/.well-known/` fallback. No TXT records. One code path.
- The mail host is independent of the domain's web host.

```dns
example.org.        MX   10 mx.provider.example.
_idmx.example.org.  SVCB 1 idmx.provider.example.
_idmx.example.net.  SVCB 1 idmx.example.net. port=8443 alpn=h2,h3
```

### 2.1 Record processing

- ServiceMode and AliasMode records are processed per RFC 9460, including
  priority ordering and failover between ServiceMode records.
- TargetName `.` means the owner name (`_idmx.<domain>`) per RFC 9460; operators
  SHOULD name an explicit target instead.
- Senders MUST ignore SvcParamKeys they do not understand, and MUST honor the
  `mandatory` key as RFC 9460 requires.
- This specification defines **no custom SvcParamKeys**.

### 2.2 Parameters

| Key | Use |
|---|---|
| `port` | TCP/UDP port of the endpoint. Default **443**. |
| `alpn` | OPTIONAL. Additional protocols, e.g. `h3`. See §4. |
| `ipv4hint`, `ipv6hint` | Per RFC 9460. |
| others | Ignored. |

### 2.3 Endpoint URL

There is **no path parameter**. The API is always at the origin root:

```text
https://<TargetName>:<port>/v1/messages
https://<TargetName>:<port>/v1/capabilities
```

- The TLS server certificate MUST be valid for **TargetName** (not for the
  recipient domain). `@authority` in the request signature is this origin.
- Providers separate tenants by hostname, not by path.

## 3. Lookup outcomes and downgrade protection

Positive discovery is **cached and pinned** (MTA-STS-style TOFU). DNSSEC is
honored when present; it is not required. Senders MUST use a resolver that
handles RR type 64; there is no substitute record type.

### 3.1 Pin

- A pin is `(recipient domain → SVCB result, expiry)`.
- The pin lifetime comes from **`discovery_pin_max_age`** (seconds) in the
  receiver's `GET /v1/capabilities` document, i.e. over authenticated TLS 1.3,
  never from DNS.
- The pin is set or refreshed on every successful capabilities fetch.
  `discovery_pin_max_age: 0` (or absent) removes the pin.
- Senders SHOULD refetch capabilities at least as often as its HTTP cache
  lifetime allows, and before a pin expires.

### 3.2 Decision table

| SVCB lookup result | No valid pin | Valid pin |
|---|---|---|
| Record found | Use IDMX; fetch capabilities; set pin | Use IDMX (fresh record); refresh pin |
| NODATA / NXDOMAIN | SMTP | Use **pinned** endpoint; treat as IDMX delivery |
| Error (SERVFAIL, timeout, resolver rejects type 64) | SMTP | Use **pinned** endpoint; treat as IDMX delivery |
| Malformed record | SMTP | Use **pinned** endpoint; treat as IDMX delivery |

- With a valid pin, a missing or failing DNS answer alone never causes SMTP
  delivery: the sender keeps using the pinned endpoint.
- If the (fresh or pinned) endpoint is unreachable or answers 5xx, the normal
  rule of `errors.md` §3 applies: retry IDMX with backoff for the bounded
  fallback window, then SMTP.

TODO: should SMTP fallback be forbidden entirely while a pin is valid
(MTA-STS `enforce` semantics) instead of allowed after the fallback window?
TODO: recommended `discovery_pin_max_age` default and upper bound.
TODO: pin-failure reporting (TLS-RPT equivalent?).

## 4. Transport

- **TLS 1.3 mandatory.**
- **HTTP/2 mandatory**: the default ALPN of this SVCB mapping is `h2`;
  receivers MUST support it. `no-default-alpn` MUST NOT be used.
- **HTTP/3 optional**, advertised with `alpn=h3`.
- HTTP/1.1 is not part of IDMX.
- Major version in the URL path (`/v1/`).

## 5. Domain migration

Migration = change the SVCB record. Senders with a pin see the fresh record
immediately (§3.2 row 1). Before decommissioning IDMX entirely, an operator
lowers `discovery_pin_max_age` to `0` and waits out the previous max-age.

## 6. Key discovery

Sender public keys live at `<selector>._idmxkey.<domain>`; see `signing.md` §4.
