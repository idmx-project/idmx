//! IDMX sender library: discovery, capabilities, signing, HTTPS delivery, and
//! the decision what to do next ([`sender::Attempt`]).
//!
//! Queueing, retry schedules, pinning, and the SMTP hand-off are the caller's
//! job; this crate performs exactly one delivery attempt and classifies it.

pub mod identity;
pub mod sender;
