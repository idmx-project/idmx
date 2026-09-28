# Reviewing IDMX v1-draft-00

Thank you for reading this. IDMX (Inter-Domain Mail Exchange) delivers mail
between domains over HTTPS instead of SMTP, while keeping `user@domain`
addresses, the RFC 5322 message format, and SMTP as a fallback.

The review is public. Feedback on v1-draft-00 by **2026-12-31** will be
considered for v1-draft-01; later feedback is still welcome and goes into the
draft after that. Each wire change the review causes gets a new draft number.
Short answers to the questions below are more useful than a full read; skip
whatever is outside your field.

## Sending feedback

Name the draft and section in every comment, for example "v1-draft-00,
`discovery.md` §3.2".

- **Email:** [feedback@idmx-project.org](mailto:feedback@idmx-project.org?subject=IDMX%20v1-draft-00%20review).
- **GitHub:** [open an issue](https://github.com/idmx-project/idmx/issues/new)
  in the idmx repository; issues are public.
- **Security issues:** email [security@idmx-project.org](mailto:security@idmx-project.org)
  privately, not in a public issue.

## What to read

| File | Content |
|---|---|
| `discovery.md` | SVCB on `_idmx.<domain>`, pinning, SMTP fallback decision table, version selection |
| `signing.md` | RFC 9421 profile (Ed25519), key records, forwarding, trace headers |
| `delivery.md` | Request body, envelope, mailbox syntax, idempotency, per-recipient results |
| `capabilities.md` | The receiver's limits document; why there are no feature flags |
| `errors.md` | Problem identifiers, retry schedule, when to fall back to SMTP |
| `iana.md` | Registrations IDMX would request |
| `openapi.yaml`, `test-vectors/` | Machine-readable companions |

Suggested order: `discovery.md`, `signing.md`, `delivery.md`, the rest as needed.

## Goals

- One HTTPS request per recipient domain, authenticated by a domain signature
  instead of IP reputation and STARTTLS.
- Lossless SMTP fallback: the message travels byte for byte, DKIM survives.
- One meaning of "supports IDMX v1": no optional behavior, no negotiation
  beyond the major version.
- Small enough for an independent implementation from the spec alone.

## Out of scope for v1

- Mailing-list semantics (lists re-originate as new deliveries).
- End-to-end encryption (`delivery.md` §7.4).
- Large-message upload (`delivery.md` §7.2).
- Reporting of pin failures (a TLS-RPT equivalent, `discovery.md` §3.2).
- Client submission and mailbox access; IDMX is server to server only.

## Questions

1. **Fallback downgrade.** A valid pin stops forged or stripped DNS answers,
   but an attacker who blocks the endpoint for the whole fallback window
   (2 hours) can still force SMTP (`discovery.md` §3.2, `errors.md` §3.1). Is
   that trade-off (outages delay mail by hours, not days) acceptable, or does
   v1 need an MTA-STS-style `enforce` mode?
2. **Domain signatures.** Is an Ed25519 RFC 9421 signature over the request,
   with keys in DNS and an exact domain match (`signing.md` §2.5), enough to
   replace IP-based sender reputation for a receiving operator? What would you
   still want to know about a sender?
3. **No feature flags.** Every new behavior means a new major version, and
   receivers serve N-1 for 24 months (`capabilities.md` §2, `discovery.md`
   §5.2). Too rigid, or right for a protocol that must interoperate from day one?
4. **Forwarding.** Forwarders re-sign as themselves and pick their own envelope
   `from` (`signing.md` §6). Does that cover aliases and forwarding as you run
   them? What breaks?
5. **Mailbox syntax.** The envelope carries the local-part as written in SMTP,
   in minimal form (`delivery.md` §3.1). Any addresses you deliver today that
   this would reject or change?
6. **Per-recipient results.** One request per domain returns `accepted`,
   `rejected`, or `deferred` per recipient (`delivery.md` §5). Does that match
   how your system decides, or do you need a result the spec lacks?
7. **Operability.** What is missing for running a receiver behind your existing
   MTA: rate limiting, abuse contact, logging, anything else?
8. **Anything you would cut.** Which part of v1 would you remove to make it
   smaller?

## Known limitations

- The fallback downgrade in question 1.
- Names (`_idmx`, `_idmxkey`, `IDMX`, `idmx`) are used unregistered
  (`iana.md`).
- The only implementation is the reference one in this repository; the spec,
  not the code, is normative.
