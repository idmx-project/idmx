# IDMX — Inter-Domain Mail Exchange

IDMX is an experimental standards project for modern HTTPS-based inter-domain
mail delivery while preserving existing `user@domain` addresses and SMTP
compatibility.

**Status: experimental.** Nothing here is stable. The spec is an early draft
and the crates implement only signing and discovery so far.

## Layout

```text
spec/            Specification (source of truth)
  openapi.yaml     OpenAPI 3.1: POST /v1/messages, GET /v1/capabilities
  delivery.md      Body layout, envelope, idempotency, per-recipient results
  discovery.md     SVCB discovery on _idmx.<domain>, pinning
  signing.md       RFC 9421 signing profile, keys at <selector>._idmxkey.<domain>
  errors.md        Error identifiers, retry and SMTP fallback rules
crates/
  idmx-core/       Envelope types, RFC 9421 sign/verify, SVCB discovery
  idmx-server/     Receiver daemon (binary: idmxd)
  idmx-client/     Sender library + CLI (binary: idmx)
devnet/          Docker Compose dev environment (placeholder)
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
