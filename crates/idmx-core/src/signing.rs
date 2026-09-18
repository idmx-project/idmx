//! The IDMX profile of HTTP Message Signatures (RFC 9421), `spec/signing.md`.
//!
//! Senders call [`sign`]. Receivers call [`UnverifiedSignature::parse`], fetch
//! the key record named by [`UnverifiedSignature::keyid`], and finish with
//! [`UnverifiedSignature::verify`], which is the only way to obtain a
//! [`VerifiedSignature`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer as _, SigningKey};
use sfv::{BareItem, Dictionary, FieldType as _, InnerList, Item, Key, ListEntry, Parser};
use sha2::{Digest as _, Sha256};

use crate::domain::Domain;
use crate::envelope::ReversePath;
use crate::idempotency::IdempotencyKey;
use crate::key::{KeyId, KeyIdError, KeyRecord};

/// Signature label used by senders. Receivers select by `tag`, not by label.
const LABEL: &str = "idmx";
const TAG: &str = "idmx-v1";
const ALGORITHM: &str = "ed25519";
const DIGEST_ALGORITHM: &str = "sha-256";

/// Allowed difference between `created` and the receiver's clock.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_mins(5);

/// Components every IDMX signature covers, in this order.
const COVERED_COMPONENTS: [&str; 7] = [
    "@method",
    "@authority",
    "@path",
    "content-digest",
    "content-type",
    "content-length",
    "idempotency-key",
];

/// The parts of a `POST /v1/messages` request that the signature covers.
///
/// `content-length` is derived from `body`; `content-digest` is computed from
/// it when signing and checked against it when verifying.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// HTTP method, upper case (`POST`).
    pub method: &'a str,
    /// Host of the receiver's IDMX origin, with `:port` unless the port is 443.
    pub authority: &'a str,
    /// Request path without query (`/v1/messages`).
    pub path: &'a str,
    /// Value of the `Content-Type` header.
    pub content_type: &'a str,
    /// The `Idempotency-Key` header.
    pub idempotency_key: &'a IdempotencyKey,
    /// Exact bytes of the HTTP content.
    pub body: &'a [u8],
}

/// Header values produced by [`sign`], to be sent with the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeaders {
    /// Value of the `Content-Digest` header.
    pub content_digest: String,
    /// Value of the `Signature-Input` header.
    pub signature_input: String,
    /// Value of the `Signature` header.
    pub signature: String,
}

/// Errors from [`sign`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    /// `created` lies before the Unix epoch.
    #[error("signing time is before the Unix epoch")]
    ClockBeforeEpoch,
    /// A component value contains a line break or is otherwise unusable.
    #[error("request component `{0}` cannot be signed")]
    InvalidComponent(&'static str),
}

/// Errors from parsing and verifying a received signature.
///
/// Every variant maps to the `invalid_signature` problem type.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// A header is not a valid structured field.
    #[error("`{0}` header is malformed")]
    MalformedHeader(&'static str),
    /// No signature carries `tag="idmx-v1"`.
    #[error("no signature with tag \"idmx-v1\"")]
    NoSignature,
    /// More than one signature carries `tag="idmx-v1"`.
    #[error("more than one signature with tag \"idmx-v1\"")]
    MultipleSignatures,
    /// The covered components differ from the list in `spec/signing.md` §2.3.
    #[error("covered components do not match the IDMX profile")]
    CoveredComponents,
    /// A required signature parameter is missing or has the wrong type.
    #[error("signature parameter `{0}` is missing or malformed")]
    Parameter(&'static str),
    /// `alg` is not `ed25519`.
    #[error("signature algorithm is not ed25519")]
    UnsupportedAlgorithm,
    /// `keyid` is not a valid key id.
    #[error(transparent)]
    KeyId(#[from] KeyIdError),
    /// `created` is outside the ±5 minute window.
    #[error("signature creation time is outside the accepted window")]
    CreatedOutOfWindow,
    /// `Content-Digest` has no `sha-256` entry.
    #[error("content-digest has no sha-256 entry")]
    MissingDigest,
    /// The `sha-256` digest does not match the received content.
    #[error("content-digest does not match the content")]
    DigestMismatch,
    /// The `Signature` header has no usable value for the selected label.
    #[error("signature value is missing or not 64 bytes")]
    SignatureValue,
    /// A request component contains a line break or is otherwise unusable.
    #[error("request component `{0}` cannot be verified")]
    InvalidComponent(&'static str),
    /// The key record has an empty `p=`.
    #[error("signing key is revoked")]
    KeyRevoked,
    /// The envelope sender's domain is not the signing domain.
    #[error("envelope sender domain `{from}` does not match signing domain `{signing}`")]
    SenderDomainMismatch {
        /// Domain of the envelope `from`.
        from: Domain,
        /// Domain of the `keyid`.
        signing: Domain,
    },
    /// The Ed25519 signature does not verify.
    #[error("signature verification failed")]
    BadSignature,
}

/// Signs `request` for the sending domain named by `keyid`.
///
/// Retries must call this again with a fresh `created` and the same
/// idempotency key.
///
/// # Errors
///
/// Returns [`SignError`] if `created` predates the Unix epoch or a request
/// component cannot be represented in a signature base.
///
/// # Examples
///
/// ```
/// use std::time::SystemTime;
///
/// use ed25519_dalek::SigningKey;
/// use idmx_core::key::{KeyId, KeyRecord};
/// use idmx_core::signing::{Request, UnverifiedSignature, sign};
///
/// let key = SigningKey::from_bytes(&[7; 32]);
/// let keyid = KeyId::new("s1", &"sender.example".parse()?)?;
/// let request = Request {
///     method: "POST",
///     authority: "idmx.receiver.example",
///     path: "/v1/messages",
///     content_type: "multipart/mixed; boundary=idmx",
///     idempotency_key: &"01J8ZQ4M9X6T3V5B7N2K0HCDEF".parse()?,
///     body: b"...",
/// };
/// let now = SystemTime::now();
///
/// let headers = sign(&request, &key, &keyid, now)?;
///
/// let unverified = UnverifiedSignature::parse(&request, &headers, now)?;
/// assert_eq!(unverified.keyid(), &keyid);
/// let published = KeyRecord::Active(key.verifying_key());
/// let verified = unverified.verify(&published)?;
/// assert_eq!(verified.signing_domain().as_str(), "sender.example");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn sign(
    request: &Request<'_>,
    key: &SigningKey,
    keyid: &KeyId,
    created: SystemTime,
) -> Result<SignatureHeaders, SignError> {
    let created = unix_seconds(created).ok_or(SignError::ClockBeforeEpoch)?;
    let content_digest = content_digest(request.body);
    let params = signature_params(created, keyid).ok_or(SignError::InvalidComponent("keyid"))?;
    let base =
        signature_base(request, &content_digest, &params).map_err(SignError::InvalidComponent)?;
    let signature = key.sign(base.as_bytes());

    Ok(SignatureHeaders {
        content_digest,
        signature_input: format!("{LABEL}={params}"),
        signature: format!("{LABEL}={}", serialize_bytes(&signature.to_bytes())),
    })
}

/// A received signature whose profile, timestamp, and content digest have been
/// checked, but whose Ed25519 signature has not.
#[derive(Debug, Clone)]
#[must_use = "an unverified signature authenticates nothing; call `verify`"]
pub struct UnverifiedSignature {
    keyid: KeyId,
    created: SystemTime,
    base: String,
    signature: Signature,
}

impl UnverifiedSignature {
    /// Performs verification steps 1–3 of `spec/signing.md` §7: selects the
    /// `idmx-v1` signature, checks parameters and covered components, checks
    /// `created` against `now`, and compares `Content-Digest` with the body.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] describing the first failed check.
    pub fn parse(
        request: &Request<'_>,
        headers: &SignatureHeaders,
        now: SystemTime,
    ) -> Result<Self, VerifyError> {
        let (label, inner_list) = select_signature(&headers.signature_input)?;
        check_covered_components(&inner_list)?;

        if string_param(&inner_list, "alg")? != ALGORITHM {
            return Err(VerifyError::UnsupportedAlgorithm);
        }
        let keyid: KeyId = string_param(&inner_list, "keyid")?.parse()?;
        let created = created_param(&inner_list)?;
        check_clock_skew(created, now)?;
        check_content_digest(&headers.content_digest, request.body)?;

        let signature = signature_value(&headers.signature, &label)?;
        let params = vec![ListEntry::InnerList(inner_list)]
            .serialize()
            .ok_or(VerifyError::MalformedHeader("signature-input"))?;
        let base = signature_base(request, headers.content_digest.trim(), &params)
            .map_err(VerifyError::InvalidComponent)?;

        Ok(Self {
            keyid,
            created,
            base,
            signature,
        })
    }

    /// The key record to fetch; its domain is the signing domain.
    #[must_use]
    pub fn keyid(&self) -> &KeyId {
        &self.keyid
    }

    /// The signing time claimed by the sender.
    #[must_use]
    pub fn created(&self) -> SystemTime {
        self.created
    }

    /// Verifies the Ed25519 signature with the record fetched for
    /// [`Self::keyid`], consuming the unverified state.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::KeyRevoked`] for a revoked record and
    /// [`VerifyError::BadSignature`] if the signature does not verify.
    pub fn verify(self, record: &KeyRecord) -> Result<VerifiedSignature, VerifyError> {
        let key = match record {
            KeyRecord::Active(key) => key,
            KeyRecord::Revoked => return Err(VerifyError::KeyRevoked),
        };
        key.verify_strict(self.base.as_bytes(), &self.signature)
            .map_err(|_| VerifyError::BadSignature)?;
        Ok(VerifiedSignature {
            keyid: self.keyid,
            created: self.created,
        })
    }

    /// The RFC 9421 signature base the signature is checked against.
    #[must_use]
    pub fn signature_base(&self) -> &str {
        &self.base
    }
}

/// Proof that a request was signed by [`Self::signing_domain`]. Only
/// [`UnverifiedSignature::verify`] creates it.
///
/// Receivers must still call [`Self::check_sender`] with the envelope sender
/// (`spec/signing.md` §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    keyid: KeyId,
    created: SystemTime,
}

impl VerifiedSignature {
    /// The domain that authorized the delivery.
    #[must_use]
    pub fn signing_domain(&self) -> &Domain {
        self.keyid.domain()
    }

    /// Verification step 6: a mailbox sender must be in the signing domain;
    /// the null reverse-path is covered by the signing domain alone.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::SenderDomainMismatch`] otherwise.
    pub fn check_sender(&self, from: &ReversePath) -> Result<(), VerifyError> {
        match from {
            ReversePath::Mailbox(mailbox) if mailbox.domain() != self.signing_domain() => {
                Err(VerifyError::SenderDomainMismatch {
                    from: mailbox.domain().clone(),
                    signing: self.signing_domain().clone(),
                })
            }
            ReversePath::Mailbox(_) | ReversePath::Null => Ok(()),
        }
    }

    /// The key that made the signature.
    #[must_use]
    pub fn keyid(&self) -> &KeyId {
        &self.keyid
    }

    /// The signing time claimed by the sender.
    #[must_use]
    pub fn created(&self) -> SystemTime {
        self.created
    }
}

fn unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn serialize_bytes(bytes: &[u8]) -> String {
    Item::new(BareItem::ByteSequence(bytes.to_vec())).serialize()
}

fn content_digest(body: &[u8]) -> String {
    format!(
        "{DIGEST_ALGORITHM}={}",
        serialize_bytes(&Sha256::digest(body))
    )
}

/// Serialized `@signature-params` value; `None` if `keyid` is not an sf-string.
fn signature_params(created: u64, keyid: &KeyId) -> Option<String> {
    let string = |value: &str| {
        sfv::String::try_from(value.to_owned())
            .ok()
            .map(BareItem::String)
    };
    let key = |name: &str| Key::try_from(name.to_owned()).ok();

    let items = COVERED_COMPONENTS
        .iter()
        .map(|name| string(name).map(Item::new))
        .collect::<Option<Vec<_>>>()?;
    let mut inner_list = InnerList::new(items);
    let created = sfv::Integer::try_from(created).ok()?;
    inner_list
        .params
        .insert(key("created")?, BareItem::Integer(created));
    inner_list
        .params
        .insert(key("keyid")?, string(keyid.as_str())?);
    inner_list.params.insert(key("alg")?, string(ALGORITHM)?);
    inner_list.params.insert(key("tag")?, string(TAG)?);

    vec![ListEntry::InnerList(inner_list)].serialize()
}

/// Builds the RFC 9421 §2.5 signature base. `Err` names the unusable component.
fn signature_base(
    request: &Request<'_>,
    content_digest: &str,
    params: &str,
) -> Result<String, &'static str> {
    let authority = request.authority.to_ascii_lowercase();
    let content_length = request.body.len().to_string();
    let values: [&str; 7] = [
        request.method,
        &authority,
        request.path,
        content_digest,
        request.content_type,
        &content_length,
        request.idempotency_key.as_str(),
    ];

    let mut lines = Vec::with_capacity(COVERED_COMPONENTS.len() + 1);
    for (name, value) in COVERED_COMPONENTS.into_iter().zip(values) {
        let value = value.trim();
        if value.is_empty() || value.contains(['\r', '\n']) {
            return Err(name);
        }
        lines.push(format!("\"{name}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {params}"));
    Ok(lines.join("\n"))
}

/// Finds the single `Signature-Input` member tagged `idmx-v1`.
fn select_signature(signature_input: &str) -> Result<(Key, InnerList), VerifyError> {
    let dictionary: Dictionary = Parser::new(signature_input)
        .parse()
        .map_err(|_| VerifyError::MalformedHeader("signature-input"))?;

    let mut tagged = dictionary
        .into_iter()
        .filter_map(|(label, entry)| match entry {
            ListEntry::InnerList(inner_list) if has_idmx_tag(&inner_list) => {
                Some((label, inner_list))
            }
            _ => None,
        });
    let selected = tagged.next().ok_or(VerifyError::NoSignature)?;
    if tagged.next().is_some() {
        return Err(VerifyError::MultipleSignatures);
    }
    Ok(selected)
}

fn has_idmx_tag(inner_list: &InnerList) -> bool {
    inner_list
        .params
        .get("tag")
        .and_then(BareItem::as_string)
        .is_some_and(|tag| tag.as_str() == TAG)
}

fn check_covered_components(inner_list: &InnerList) -> Result<(), VerifyError> {
    let covered = inner_list.items.iter().map(|item| {
        item.params
            .is_empty()
            .then(|| item.bare_item.as_string().map(sfv::StringRef::as_str))
            .flatten()
    });
    if covered.eq(COVERED_COMPONENTS.into_iter().map(Some)) {
        Ok(())
    } else {
        Err(VerifyError::CoveredComponents)
    }
}

fn string_param<'a>(inner_list: &'a InnerList, name: &'static str) -> Result<&'a str, VerifyError> {
    inner_list
        .params
        .get(name)
        .and_then(BareItem::as_string)
        .map(sfv::StringRef::as_str)
        .ok_or(VerifyError::Parameter(name))
}

fn created_param(inner_list: &InnerList) -> Result<SystemTime, VerifyError> {
    inner_list
        .params
        .get("created")
        .and_then(BareItem::as_integer)
        .and_then(|created| u64::try_from(i64::from(created)).ok())
        .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .ok_or(VerifyError::Parameter("created"))
}

fn check_clock_skew(created: SystemTime, now: SystemTime) -> Result<(), VerifyError> {
    let skew = match now.duration_since(created) {
        Ok(skew) => skew,
        Err(ahead) => ahead.duration(),
    };
    if skew <= MAX_CLOCK_SKEW {
        Ok(())
    } else {
        Err(VerifyError::CreatedOutOfWindow)
    }
}

fn check_content_digest(content_digest: &str, body: &[u8]) -> Result<(), VerifyError> {
    let dictionary: Dictionary = Parser::new(content_digest)
        .parse()
        .map_err(|_| VerifyError::MalformedHeader("content-digest"))?;
    let Some(ListEntry::Item(item)) = dictionary.get(DIGEST_ALGORITHM) else {
        return Err(VerifyError::MissingDigest);
    };
    let digest = item
        .bare_item
        .as_byte_sequence()
        .ok_or(VerifyError::MissingDigest)?;

    if digest == Sha256::digest(body).as_slice() {
        Ok(())
    } else {
        Err(VerifyError::DigestMismatch)
    }
}

fn signature_value(signature: &str, label: &Key) -> Result<Signature, VerifyError> {
    let dictionary: Dictionary = Parser::new(signature)
        .parse()
        .map_err(|_| VerifyError::MalformedHeader("signature"))?;
    let Some(ListEntry::Item(item)) = dictionary.get(label.as_str()) else {
        return Err(VerifyError::SignatureValue);
    };
    item.bare_item
        .as_byte_sequence()
        .and_then(|bytes| Signature::from_slice(bytes).ok())
        .ok_or(VerifyError::SignatureValue)
}
