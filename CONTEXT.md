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

**Draft**:
An immutable, tagged revision of the specification, named `v<major>-draft-<NN>` (e.g.
`v1-draft-00`). The `v<major>` part is the protocol version; the draft number is not.
_Avoid_: release, spec version

**Editor's draft**:
The current, untagged state of the specification; it may change at any time and is not citable.
_Avoid_: latest spec, nightly, main

**Receiver**:
The IDMX endpoint of a domain, found via its `_idmx` SVCB record; it accepts deliveries from other
domains and hands them to the domain's local delivery. Client access to mailboxes is not part of it.
_Avoid_: IDMX server, IDMX mail server
