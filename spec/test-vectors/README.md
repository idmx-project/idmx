# Test vectors

Implementation-independent vectors for `signing.md`. Ed25519 signatures are
deterministic, so a conforming signer reproduces `expected` byte for byte.

| File | Content |
|---|---|
| `signing-basic.json` | Inputs and expected `Content-Digest`, `Signature-Input`, signature base, and `Signature` |
| `signing-basic.body` | Exact HTTP content (CRLF line endings; do not normalize) |

The private key is the public RFC 8032 §7.1 TEST 1 key. Never use it outside tests.

The multipart layout of the body is illustrative; the signature treats the
content as opaque bytes.

License: CC-BY-4.0 (see `../LICENSE`).
