//! Where the receiver gets sender public keys from.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use idmx_core::discovery::{KeyLookupError, lookup_key};
use idmx_core::key::{KeyId, KeyRecord};

/// `spec/signing.md` §4.3: never cache a key record longer than this.
const MAX_KEY_TTL: Duration = Duration::from_hours(1);
/// `spec/signing.md` §4.3: never cache a missing record longer than this.
const MAX_NEGATIVE_TTL: Duration = Duration::from_mins(5);

/// Result of a key lookup, boxed so that [`KeySource`] is object safe.
pub type KeyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<KeyRecord, KeyLookupError>> + Send + 'a>>;

/// Fetches the key record named by a `keyid`. DNS in production; tests
/// substitute a fixed key.
pub trait KeySource: Send + Sync {
    /// Looks up `keyid`.
    fn fetch<'a>(&'a self, keyid: &'a KeyId) -> KeyFuture<'a>;
}

/// [`KeySource`] backed by DNS. Caching is the resolver's, bounded as the
/// spec requires.
pub struct DnsKeySource {
    resolver: TokioResolver,
}

impl DnsKeySource {
    /// Builds a resolver from the system configuration with the cache bounds
    /// of `spec/signing.md` §4.3.
    ///
    /// # Errors
    ///
    /// Returns the resolver's error if the system DNS configuration is unusable.
    pub fn from_system_conf() -> Result<Self, NetError> {
        let mut builder = TokioResolver::builder_tokio()?;
        let options = builder.options_mut();
        options.positive_max_ttl = Some(MAX_KEY_TTL);
        options.negative_max_ttl = Some(MAX_NEGATIVE_TTL);
        Ok(Self {
            resolver: builder.build()?,
        })
    }
}

impl KeySource for DnsKeySource {
    fn fetch<'a>(&'a self, keyid: &'a KeyId) -> KeyFuture<'a> {
        Box::pin(lookup_key(&self.resolver, keyid))
    }
}
