//! The IDMX receiver: a front door beside the MTA that accepts signed
//! deliveries over HTTPS and hands them to local delivery.
//!
//! [`app::router`] is the whole HTTP surface; `main.rs` only loads the
//! [`config::Config`] and serves it.

pub mod app;
pub mod config;
pub mod error;
pub mod idempotency;
pub mod keys;
pub mod maildir;
pub mod trace;
