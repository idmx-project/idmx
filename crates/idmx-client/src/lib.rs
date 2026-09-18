//! IDMX sender library: discovery, capabilities, signing, HTTPS delivery
//! ([`sender`]), discovery pins ([`pin`]), the retry schedule ([`schedule`]),
//! and a spool that ties them together with the SMTP hand-off ([`queue`],
//! [`smtp`]) and bounces what fails for good ([`dsn`]).

pub mod dsn;
pub mod identity;
pub mod pin;
pub mod queue;
pub mod schedule;
pub mod sender;
pub mod smtp;
