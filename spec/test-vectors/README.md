# Test vectors

Implementation-independent vectors for `signing.md` and `delivery.md`. Ed25519 signatures are
deterministic, so a conforming signer reproduces `expected` byte for byte.

| File | Content |
|---|---|
| `signing-basic.json` | Inputs and expected `Content-Digest`, `Signature-Input`, signature base, and `Signature` |
| `signing-basic.body` | Exact HTTP content (CRLF line endings; do not normalize) |
| `delivery-basic.json` | Body layout: decoding `signing-basic.body` must yield this envelope and `delivery-basic.eml` |
| `delivery-basic.eml` | The raw message inside the body (CRLF; do not normalize) |
| `delivery-result.json` | A `200` response with one recipient per status |

The private key is the public RFC 8032 §7.1 TEST 1 key. Never use it outside tests.

The signature treats the body as opaque bytes; its layout is checked by the
`delivery-*` vectors.

License: CC-BY-4.0 (see `../LICENSE`).
