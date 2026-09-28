# IDMX — Inter-Domain Mail Exchange

IDMX is an experimental standards project for modern HTTPS-based inter-domain
mail delivery while preserving existing `user@domain` addresses and SMTP
compatibility.

**Status: experimental.** Nothing here is stable. The spec is heading for
`v1-draft-00`, a draft for review. The reference implementation covers signing,
discovery, the receiver (`idmxd`), and a sender (`idmx send`) with retries,
pinning, a spool queue, SMTP fallback, and bounces. The devnet demonstrates
modern → modern delivery, SMTP fallback, and a conformance run against both
receivers.

## Layout

```text
spec/            Specification (source of truth)
  openapi.yaml     OpenAPI 3.1: POST /v1/messages, GET /v1/capabilities
  delivery.md      Body layout, envelope, idempotency, per-recipient results
  discovery.md     SVCB discovery on _idmx.<domain>, pinning
  signing.md       RFC 9421 signing profile, keys at <selector>._idmxkey.<domain>
  capabilities.md  Capabilities document: versions, limits, no feature flags
  errors.md        Error identifiers, retry and SMTP fallback rules
  iana.md          Registrations IDMX would request
  REVIEW.md        Guide and questions for draft reviewers
  test-vectors/    Signing, delivery, and mailbox vectors
crates/
  idmx-core/       Envelope types, RFC 9421 sign/verify, SVCB discovery
  idmx-server/     Receiver daemon (binary: idmxd)
  idmx-client/     Sender library + CLI (binary: idmx)
  idmx-conformance/  Black-box receiver checks (binary: idmx-conformance <origin>)
devnet/          Local IDMX network in containers (podman or docker); see devnet/README.md
docs/            Design notes (IDMX_IDEAS.md)
```

The specification is implementation-independent. The Rust code demonstrates
the specification; it never defines it.

## Building

```bash
cargo test
```

## Licensing

- **Code and `spec/openapi.yaml`**: dual-licensed under
  [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
- **Specification prose (`spec/*.md`)**: [CC-BY-4.0](spec/LICENSE).

## Contributing

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).
Sign off every commit (`git commit -s`), which adds a `Signed-off-by:` line
certifying you have the right to submit the work under the licenses above.
