//! SVCB discovery on `_idmx.<domain>` (`spec/discovery.md` §2) and key record
//! lookup (`spec/signing.md` §4).
//!
//! This module only answers "what does DNS say right now". Pinning
//! (`spec/discovery.md` §3) needs the capabilities document and persistent
//! state, and lives with the sender.

use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::rdata::SVCB;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::domain::Domain;
use crate::key::{KeyId, KeyRecord, KeyRecordError};

const DEFAULT_PORT: u16 = 443;
/// RFC 9460 §2.4.2 lets clients bound alias chains.
const MAX_ALIAS_HOPS: usize = 4;

/// One IDMX origin advertised by a `ServiceMode` SVCB record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    http3: bool,
}

impl Endpoint {
    /// SVCB `TargetName`, lower case, without trailing dot; the TLS
    /// certificate must match it.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// TCP (and, for HTTP/3, UDP) port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the record advertises `alpn=h3` in addition to mandatory `h2`.
    #[must_use]
    pub fn supports_http3(&self) -> bool {
        self.http3
    }

    /// The `@authority` value for requests to this endpoint: `host`, with
    /// `:port` unless the port is 443.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.port == DEFAULT_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// What DNS currently says about a domain's IDMX support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// Usable endpoints, most preferred first.
    Supported(Vec<Endpoint>),
    /// No record (NODATA / NXDOMAIN), or no record this implementation can use.
    Unsupported,
}

/// Errors from [`discover`]. With a valid pin these are IDMX temporary
/// failures; without one the sender uses SMTP (`spec/discovery.md` §3.2).
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// `_idmx.<domain>` is not a valid DNS name (the domain is too long).
    #[error("`_idmx.{0}` is not a valid DNS name")]
    InvalidOwnerName(Domain),
    /// `AliasMode` records chain further than this implementation follows.
    #[error("SVCB alias chain is too long")]
    AliasChainTooLong,
    /// The DNS lookup failed (SERVFAIL, timeout, resolver rejects type 64, …).
    #[error("SVCB lookup failed: {0}")]
    Lookup(#[source] NetError),
}

/// Looks up `_idmx.<domain>` and follows `AliasMode` records.
///
/// # Errors
///
/// Returns [`DiscoveryError`] if the owner name is invalid or the lookup fails for a
/// reason other than "no such record".
pub async fn discover(
    resolver: &TokioResolver,
    domain: &Domain,
) -> Result<Discovery, DiscoveryError> {
    let invalid_domain = |_| DiscoveryError::InvalidOwnerName(domain.clone());
    let mut owner = Name::from_ascii(format!("_idmx.{domain}.")).map_err(invalid_domain)?;

    for _ in 0..=MAX_ALIAS_HOPS {
        let Some(records) = lookup_svcb(resolver, owner.clone()).await? else {
            return Ok(Discovery::Unsupported);
        };
        match resolve_rrset(&owner, &records) {
            Resolution::Alias(target) => owner = target,
            Resolution::Endpoints(endpoints) if endpoints.is_empty() => {
                return Ok(Discovery::Unsupported);
            }
            Resolution::Endpoints(endpoints) => return Ok(Discovery::Supported(endpoints)),
        }
    }
    Err(DiscoveryError::AliasChainTooLong)
}

async fn lookup_svcb(
    resolver: &TokioResolver,
    owner: Name,
) -> Result<Option<Vec<SVCB>>, DiscoveryError> {
    match resolver.lookup(owner, RecordType::SVCB).await {
        Ok(lookup) => Ok(Some(
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::SVCB(svcb) => Some(svcb.clone()),
                    _ => None,
                })
                .collect(),
        )),
        Err(error) if error.is_no_records_found() => Ok(None),
        Err(error) => Err(DiscoveryError::Lookup(error)),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Resolution {
    Alias(Name),
    Endpoints(Vec<Endpoint>),
}

/// Applies RFC 9460 §2.4 to one SVCB `RRset` owned by `owner`.
fn resolve_rrset(owner: &Name, records: &[SVCB]) -> Resolution {
    if let Some(alias) = records.iter().find(|record| record.svc_priority == 0) {
        return Resolution::Alias(target_of(owner, alias));
    }

    let mut usable: Vec<_> = records
        .iter()
        .filter_map(|record| Some((record.svc_priority, endpoint(owner, record)?)))
        .collect();
    usable.sort_by_key(|(priority, _)| *priority);
    Resolution::Endpoints(usable.into_iter().map(|(_, endpoint)| endpoint).collect())
}

/// `TargetName` `.` means the owner name (RFC 9460 §2.5).
fn target_of(owner: &Name, record: &SVCB) -> Name {
    if record.target_name.is_root() {
        owner.clone()
    } else {
        record.target_name.clone()
    }
}

/// `None` if the record demands something this implementation cannot honor.
fn endpoint(owner: &Name, record: &SVCB) -> Option<Endpoint> {
    let mut port = DEFAULT_PORT;
    let mut http3 = false;

    for (_, value) in &record.svc_params {
        match value {
            SvcParamValue::Port(value) => port = *value,
            SvcParamValue::Alpn(alpn) => http3 = alpn.0.iter().any(|id| id == "h3"),
            // `spec/discovery.md` §4: h2 is the mandatory default protocol.
            SvcParamValue::NoDefaultAlpn => return None,
            SvcParamValue::Mandatory(mandatory)
                if !mandatory.0.iter().copied().all(is_understood) =>
            {
                return None;
            }
            _ => {}
        }
    }

    let mut host = target_of(owner, record).to_ascii().to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    Some(Endpoint { host, port, http3 })
}

fn is_understood(key: SvcParamKey) -> bool {
    matches!(
        key,
        SvcParamKey::Mandatory
            | SvcParamKey::Alpn
            | SvcParamKey::Port
            | SvcParamKey::Ipv4Hint
            | SvcParamKey::Ipv6Hint
    )
}

/// Errors from [`lookup_key`].
#[derive(Debug, thiserror::Error)]
pub enum KeyLookupError {
    /// No TXT record at the key name. Permanent: `invalid_signature`.
    #[error("no key record at `{0}`")]
    NotFound(KeyId),
    /// More than one `v=IDMX1` record. Permanent: `invalid_signature`.
    #[error("more than one key record at `{0}`")]
    Ambiguous(KeyId),
    /// The record does not parse. Permanent: `invalid_signature`.
    #[error("key record at `{keyid}` is malformed: {source}")]
    Malformed {
        /// Name of the offending record.
        keyid: KeyId,
        /// Why it does not parse.
        source: KeyRecordError,
    },
    /// The DNS lookup failed. Temporary: `temporary_failure`.
    #[error("key lookup failed: {0}")]
    Lookup(#[source] NetError),
}

impl KeyLookupError {
    /// Whether the sender should be told to retry (`temporary_failure`)
    /// instead of receiving `invalid_signature`.
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        matches!(self, Self::Lookup(_))
    }
}

/// Fetches the key record named by `keyid`, following selector CNAMEs.
///
/// A [`KeyRecord::Revoked`] result is returned as `Ok`; callers must treat it
/// as `invalid_signature`.
///
/// # Errors
///
/// Returns [`KeyLookupError`]; see [`KeyLookupError::is_temporary`].
pub async fn lookup_key(
    resolver: &TokioResolver,
    keyid: &KeyId,
) -> Result<KeyRecord, KeyLookupError> {
    let lookup = match resolver.lookup(format!("{keyid}."), RecordType::TXT).await {
        Ok(lookup) => lookup,
        Err(error) if error.is_no_records_found() => {
            return Err(KeyLookupError::NotFound(keyid.clone()));
        }
        Err(error) => return Err(KeyLookupError::Lookup(error)),
    };

    let txt_values: Vec<String> = lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part))
                    .collect(),
            ),
            _ => None,
        })
        .collect();
    select_key_record(keyid, &txt_values)
}

/// Picks the single `v=IDMX1` record among the TXT values at a key name.
fn select_key_record(keyid: &KeyId, txt_values: &[String]) -> Result<KeyRecord, KeyLookupError> {
    let mut candidates = txt_values
        .iter()
        .filter(|value| value.trim_start().starts_with("v=IDMX1"));

    let record = candidates
        .next()
        .ok_or_else(|| KeyLookupError::NotFound(keyid.clone()))?;
    if candidates.next().is_some() {
        return Err(KeyLookupError::Ambiguous(keyid.clone()));
    }
    record.parse().map_err(|source| KeyLookupError::Malformed {
        keyid: keyid.clone(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::rr::rdata::svcb::{Alpn, Mandatory};

    use super::*;

    fn name(name: &str) -> Name {
        Name::from_ascii(name).unwrap()
    }

    fn owner() -> Name {
        name("_idmx.example.org.")
    }

    fn service(priority: u16, target: &str, params: Vec<(SvcParamKey, SvcParamValue)>) -> SVCB {
        SVCB::new(priority, name(target), params)
    }

    fn endpoint_at(host: &str, port: u16, http3: bool) -> Endpoint {
        Endpoint {
            host: host.to_owned(),
            port,
            http3,
        }
    }

    mod resolve_rrset {
        use super::*;

        #[test]
        fn defaults_to_port_443_without_http3() {
            let records = [service(1, "idmx.provider.example.", vec![])];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(
                resolution,
                Resolution::Endpoints(vec![endpoint_at("idmx.provider.example", 443, false)])
            );
        }

        #[test]
        fn reads_port_and_h3_alpn() {
            let params = vec![
                (SvcParamKey::Port, SvcParamValue::Port(8443)),
                (
                    SvcParamKey::Alpn,
                    SvcParamValue::Alpn(Alpn(vec!["h2".to_owned(), "h3".to_owned()])),
                ),
            ];
            let records = [service(1, "idmx.example.net.", params)];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(
                resolution,
                Resolution::Endpoints(vec![endpoint_at("idmx.example.net", 8443, true)])
            );
        }

        #[test]
        fn orders_endpoints_by_priority() {
            let records = [
                service(20, "backup.example.", vec![]),
                service(10, "primary.example.", vec![]),
            ];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(
                resolution,
                Resolution::Endpoints(vec![
                    endpoint_at("primary.example", 443, false),
                    endpoint_at("backup.example", 443, false),
                ])
            );
        }

        #[test]
        fn alias_record_wins_over_service_records() {
            let records = [
                service(1, "idmx.provider.example.", vec![]),
                service(0, "alias.provider.example.", vec![]),
            ];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(
                resolution,
                Resolution::Alias(name("alias.provider.example."))
            );
        }

        #[test]
        fn dot_target_means_owner_name() {
            let records = [service(1, ".", vec![])];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(
                resolution,
                Resolution::Endpoints(vec![endpoint_at("_idmx.example.org", 443, false)])
            );
        }

        #[test]
        fn skips_record_with_no_default_alpn() {
            let params = vec![(SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn)];
            let records = [service(1, "idmx.provider.example.", params)];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(resolution, Resolution::Endpoints(vec![]));
        }

        #[test]
        fn skips_record_with_unknown_mandatory_key() {
            let params = vec![(
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Key(65280)])),
            )];
            let records = [service(1, "idmx.provider.example.", params)];

            let resolution = resolve_rrset(&owner(), &records);

            assert_eq!(resolution, Resolution::Endpoints(vec![]));
        }
    }

    mod endpoint_authority {
        use super::*;

        #[test]
        fn omits_default_port() {
            let authority = endpoint_at("idmx.provider.example", 443, false).authority();

            assert_eq!(authority, "idmx.provider.example");
        }

        #[test]
        fn includes_other_port() {
            let authority = endpoint_at("idmx.provider.example", 8443, false).authority();

            assert_eq!(authority, "idmx.provider.example:8443");
        }
    }

    mod select_key_record {
        use super::*;

        fn keyid() -> KeyId {
            "s1._idmxkey.sender.example".parse().unwrap()
        }

        #[test]
        fn ignores_unrelated_txt_records() {
            let values = [
                "v=spf1 -all".to_owned(),
                "v=IDMX1; k=ed25519; p=".to_owned(),
            ];

            let record = select_key_record(&keyid(), &values);

            assert!(
                matches!(record, Ok(KeyRecord::Revoked)),
                "unexpected: {record:?}"
            );
        }

        #[test]
        fn fails_when_no_idmx_record_present() {
            let values = ["v=spf1 -all".to_owned()];

            let error = select_key_record(&keyid(), &values).unwrap_err();

            assert!(
                matches!(error, KeyLookupError::NotFound(_)),
                "unexpected: {error}"
            );
        }

        #[test]
        fn fails_when_several_idmx_records_present() {
            let values = [
                "v=IDMX1; k=ed25519; p=".to_owned(),
                "v=IDMX1; k=ed25519; p=".to_owned(),
            ];

            let error = select_key_record(&keyid(), &values).unwrap_err();

            assert!(
                matches!(error, KeyLookupError::Ambiguous(_)),
                "unexpected: {error}"
            );
        }

        #[test]
        fn malformed_record_is_permanent() {
            let values = ["v=IDMX1; k=rsa; p=".to_owned()];

            let error = select_key_record(&keyid(), &values).unwrap_err();

            assert!(!error.is_temporary(), "unexpected: {error}");
        }
    }
}
