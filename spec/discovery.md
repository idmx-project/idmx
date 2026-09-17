# IDMX Discovery

Status: **draft skeleton**. Decisions copied from `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17).
License: CC-BY-4.0 (see `LICENSE`).

## 1. Overview

A sender extracts the recipient domain from `user@domain` and looks up IDMX
support in DNS. No record → normal MX lookup and SMTP.

## 2. SVCB record

- Discovery is an **SVCB record on `_idmx.<domain>`**.
- No `/.well-known/` fallback. No TXT records. One code path.
- The mail host is independent of the domain's web host.

```dns
example.org.        MX   10 mx.provider.example.
_idmx.example.org.  SVCB 1 idmx.provider.example.
```

TODO: exact SVCB parameters (port, ALPN, path, pin max-age location).
TODO: behavior with resolvers / DNS hosts lacking SVCB support.

## 3. Downgrade protection (cache + pin)

- Positive discovery results are **cached and pinned with a max-age**
  (MTA-STS-style TOFU).
- DNSSEC is honored when present; it is not required.
- A stripped DNS answer must not silently permit SMTP downgrade while a pin is valid.

TODO: pin max-age defaults.
TODO: pin-failure reporting (TLS-RPT equivalent?).

## 4. Transport

- **TLS 1.3 mandatory.**
- Major version in the URL path (`/v1/`).

## 5. Domain migration

Migration = change the SVCB record; pin max-age bounds the transition.

## 6. Key discovery

Sender public keys live at `<selector>._idmxkey.<domain>`; see `signing.md`.
