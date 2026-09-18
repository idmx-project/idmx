//! Core building blocks for IDMX (Inter-Domain Mail Exchange).
//!
//! - [`domain`]: the validated DNS domain, IDMX's unit of identity.
//! - [`mailbox`], [`envelope`], [`idempotency`], [`body`]: the delivery request
//!   (`spec/delivery.md` §2–§4).
//! - [`result`], [`problem`]: the delivery response (`spec/delivery.md` §5,
//!   `spec/errors.md`).
//! - [`key`]: key identifiers and the DNS key record (`spec/signing.md` §4).
//! - [`signing`]: the RFC 9421 signing profile (`spec/signing.md` §2, §3, §7).
//! - [`discovery`]: SVCB discovery on `_idmx.<domain>` and key lookup
//!   (`spec/discovery.md` §2).
//!
//! The normative definition lives in `spec/`; this crate demonstrates the
//! specification and never defines it.

pub mod body;
pub mod discovery;
pub mod domain;
pub mod envelope;
pub mod idempotency;
pub mod key;
pub mod mailbox;
pub mod problem;
pub mod result;
pub mod signing;
