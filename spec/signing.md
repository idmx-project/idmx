# IDMX Signing

Status: **draft skeleton**. Decisions copied from `docs/IDMX_IDEAS.md` (Decisions, 2026-09-17).
License: CC-BY-4.0 (see `LICENSE`).

## 1. Overview

Every delivery request is authenticated with **HTTP Message Signatures
(RFC 9421)** by the sending domain. Authentication is mandatory in v1.

## 2. RFC 9421 profile

TODO: algorithm (Ed25519?).
TODO: covered components.
TODO: body digest (`Content-Digest`, RFC 9530) and canonicalization.

## 3. Timestamp and replay

- The signature covers a `created` timestamp; receivers accept **±5 min** skew.
- Retries **re-sign with a fresh timestamp** but keep the **same idempotency key**.
- Receivers remember idempotency keys for at least the maximum sender retry
  window (e.g. 7 days) and return the original result for duplicates.

## 4. Key discovery

- Public keys are published in DNS at **`<selector>._idmxkey.<domain>`**.

TODO: key record format.
TODO: rotation and revocation procedure.

## 5. Delegated sending

- **DKIM-style selector CNAME** to provider-hosted keys; one selector per provider.
- Providers rotate keys freely.

## 6. Forwarding: two-layer signatures

- Transport signature = the **current hop's domain**.
- Message-level DKIM inside the MIME body = the **original author**.
- Alias expansion and list explosion re-originate as new deliveries signed by
  the forwarding domain (v1: receiver-internal, spec otherwise silent).

## 7. Receiver trace headers

The receiver adds a trace header and `Authentication-Results` before handing
the message to local delivery.

TODO: trace / `Authentication-Results` header format for IDMX-received mail.

## 8. Test vectors

TODO: test vectors (to live in `spec/`).
