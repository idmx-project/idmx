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
  receiver's `GET /v1/capabilities` document (`capabilities.md`), i.e. over
  authenticated TLS 1.3, never from DNS.
- The pin is set or refreshed on every successful capabilities fetch.
  `discovery_pin_max_age: 0` (or absent) removes the pin.
- Receivers SHOULD advertise **604 800** (7 days). Senders MUST treat values
  above **31 557 600** (1 year) as 31 557 600.
- Senders refetch capabilities as its cache lifetime requires
  (`capabilities.md` §4), and SHOULD refetch before a pin expires.

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

- A valid pin does **not** forbid that fallback (no MTA-STS `enforce`
  semantics in v1). The pin protects against forged or stripped DNS answers;
  an attacker who can block the endpoint itself for the whole fallback window
  can still force SMTP. This is a known v1 limitation, accepted so that a
  receiver outage delays mail by hours, not days.

Pin-failure reporting (a TLS-RPT equivalent that tells a receiver about
failed pinned deliveries) is not part of v1. It would arrive with a later
major version, possibly reusing the RFC 8460 report format.

## 4. Transport

- **TLS 1.3 mandatory.**
- **HTTP/2 mandatory**: the default ALPN of this SVCB mapping is `h2`;
  receivers MUST support it. `no-default-alpn` MUST NOT be used.
- **HTTP/3 optional**, advertised with `alpn=h3`.
- HTTP/1.1 is not part of IDMX.
- Major version in the URL path (`/v1/`).

## 5. Version selection

The major version lives in the URL path. Minor evolution inside a major
version needs no negotiation: it is additive and informational only (unknown
fields are ignored). There is no optional behavior inside a major version
(`capabilities.md` §2).

- Every capabilities document (`GET /vN/capabilities`) lists **all** major
  versions the receiver serves in `versions`, e.g. `["v1", "v2"]`. An absent
  `versions` means `["v1"]`.
- A sender fetches the capabilities document of the highest major version it
  knows the receiver serves (remembered alongside the pin); on first contact,
  of the lowest major version the sender itself supports.
- The sender then delivers using the **highest major version both sides
  support**. Senders MUST NOT probe version paths to find out what exists.
- The list arrives over authenticated TLS, so it cannot be stripped by a DNS
  attacker; it has the same trust as the pin.
- **No common major version**: the two systems cannot speak IDMX to each
  other. The sender handles this as `unsupported_version` and MAY fall back to
  SMTP immediately, even while a pin is valid (`errors.md` §3). This is not a
  downgrade: the pin protects against forged "no IDMX" answers from DNS, not
  against an authenticated receiver stating which versions it speaks.

### 5.1 First contact with a retired version

The capabilities path a sender fetches on first contact may belong to a major
version the receiver no longer serves. The answer still tells the sender what
exists:

- Every `unsupported_version` problem (`errors.md` §2) MUST carry a
  **`versions`** member: all major versions the receiver serves, in the same
  format as the capabilities member.
- A sender that supports one of the listed versions fetches that version's
  capabilities document and continues as above. This follows an authenticated
  statement of the receiver; it is not path probing.
- A problem without a usable `versions` member, or a list without any version
  the sender supports, is "no common major version".

### 5.2 Deprecation of major versions

- A receiver that serves major version N MUST also serve **N-1** until at
  least **24 months** after the specification of version N was published as
  final. After that it MAY stop serving N-1. There is no obligation towards
  versions older than N-1.
- Senders SHOULD keep supporting N-1 for the same period. A sender that drops
  it earlier only harms its own deliveries: they go out over SMTP.
- A retired version costs IDMX delivery, never mail: the affected pairs fall
  back to SMTP under the "no common major version" rule above.

## 6. Domain migration

Migration = change the SVCB record. Senders with a pin see the fresh record
immediately (§3.2 row 1). Before decommissioning IDMX entirely, an operator
lowers `discovery_pin_max_age` to `0` and waits out the previous max-age.

## 7. Key discovery

Sender public keys live at `<selector>._idmxkey.<domain>`; see `signing.md` §4.
