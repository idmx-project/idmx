//! Core building blocks for IDMX (Inter-Domain Mail Exchange).
//!
//! - [`key`]: key identifiers and the DNS key record (`spec/signing.md` §4).
//! - [`signing`]: the RFC 9421 signing profile (`spec/signing.md` §2, §3, §7).
//! - [`discovery`]: SVCB discovery on `_idmx.<domain>` and key lookup
//!   (`spec/discovery.md` §2).
//!
//! The normative definition lives in `spec/`; this crate demonstrates the
//! specification and never defines it.

pub mod discovery;
pub mod key;
pub mod signing;
