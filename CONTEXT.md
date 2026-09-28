# IDMX

IDMX (Inter-Domain Mail Exchange) delivers mail between domains over HTTPS while keeping
`user@domain` addresses and SMTP as the fallback.

## Language

**Local-part**:
The part of a mailbox before the last `@`, in the form it is written in SMTP (RFC 5321/6531
dot-string or quoted-string). Opaque to the sender; only the receiving domain interprets it.
_Avoid_: username, user

**Signing domain**:
The domain whose key signs a delivery; the envelope `from`, when present, is in this domain.
_Avoid_: sender domain, origin domain

**Forwarder**:
A domain that receives a message and re-originates it as a new delivery under its own signing
domain.
_Avoid_: relay, redirector
