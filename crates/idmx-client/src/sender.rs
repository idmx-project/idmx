//! One delivery attempt and its classification (`spec/errors.md`).

use std::time::{Duration, SystemTime};

use hickory_resolver::TokioResolver;
use idmx_core::body::encode;
use idmx_core::capabilities::Capabilities;
use idmx_core::discovery::{Discovery, DiscoveryError, Endpoint, discover};
use idmx_core::domain::Domain;
use idmx_core::envelope::{Envelope, ReversePath};
use idmx_core::idempotency::IdempotencyKey;
use idmx_core::problem::{FailureClass, Problem, ProblemKind, ProblemType};
use idmx_core::result::DeliveryResult;
use idmx_core::signing::{self, SignError, sign};
use reqwest::{Response, StatusCode, header};

use crate::identity::Identity;
use crate::pin::{PinError, PinStore};
use crate::schedule::SmtpFallback;

const MESSAGES_PATH: &str = "/v1/messages";
const CAPABILITIES_PATH: &str = "/v1/capabilities";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Local failures that prevent an attempt from being made at all.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// The envelope sender is not in the domain of the signing key.
    #[error("envelope sender is not in the signing domain `{0}`")]
    SenderDomain(String),
    /// The envelope cannot be serialized.
    #[error("encoding the envelope: {0}")]
    Encode(#[from] serde_json::Error),
    /// The request cannot be signed.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The pin learned from the receiver cannot be stored.
    #[error(transparent)]
    Pin(#[from] PinError),
}

/// Why SMTP may be used right away.
#[derive(Debug)]
pub enum SmtpReason {
    /// The domain publishes no usable `_idmx` SVCB record.
    NotAdvertised,
    /// Discovery failed and no valid pin exists (`spec/discovery.md` §3.2).
    DiscoveryFailed(DiscoveryError),
    /// Receiver and sender share no major version (`spec/discovery.md` §5).
    NoCommonVersion,
}

/// Outcome of one attempt, telling the caller what it may do next.
#[derive(Debug)]
#[must_use]
pub enum Attempt {
    /// The receiver processed the request; act on each recipient's result.
    Completed(DeliveryResult),
    /// Permanent request-level failure: bounce. Never retry, never use SMTP.
    Rejected(Problem),
    /// Temporary failure: retry IDMX with the same idempotency key.
    TryLater {
        /// Whether this failure counts towards SMTP fallback (5xx) or forbids
        /// it (e.g. `rate_limited`).
        fallback: SmtpFallback,
        /// The receiver's problem document, if it sent one.
        problem: Option<Problem>,
        /// The receiver's `Retry-After`, if it sent one in seconds.
        retry_after: Option<Duration>,
    },
    /// No usable HTTP response: connection, TLS, or protocol failure, or an
    /// unreadable body. Handled like a temporary failure; the retry may go to
    /// another endpoint of the domain.
    Unreachable(reqwest::Error),
    /// IDMX is not available for this domain; SMTP may be used now.
    UseSmtp(SmtpReason),
}

/// A `reqwest` client builder with the transport rules of `spec/discovery.md`
/// §4 applied: rustls with the `ring` provider, TLS 1.3 as the minimum.
pub fn http_client_builder() -> reqwest::ClientBuilder {
    // A failed install only means a provider is already in place.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .tls_version_min(reqwest::tls::Version::TLS_1_3)
        // A black-holed endpoint must not stall the queue.
        .connect_timeout(CONNECT_TIMEOUT)
}

/// Performs delivery attempts for one sending identity.
pub struct Sender {
    http: reqwest::Client,
    resolver: TokioResolver,
    identity: Identity,
}

impl Sender {
    /// Build `http` from [`http_client_builder`].
    #[must_use]
    pub fn new(http: reqwest::Client, resolver: TokioResolver, identity: Identity) -> Self {
        Self {
            http,
            resolver,
            identity,
        }
    }

    /// Discovers the recipient domain's endpoints and attempts delivery to
    /// them in priority order. Follows the decision table of
    /// `spec/discovery.md` §3.2: without a usable DNS answer a valid pin
    /// keeps delivery on IDMX, and every capabilities fetch refreshes the pin.
    ///
    /// # Errors
    ///
    /// Returns [`SendError`] if the request cannot be built or the pin cannot
    /// be stored. Everything that happens on the network is reported as an
    /// [`Attempt`].
    pub async fn send(
        &self,
        envelope: &Envelope,
        message: &[u8],
        idempotency_key: &IdempotencyKey,
        pins: &mut PinStore,
    ) -> Result<Attempt, SendError> {
        let domain = envelope.recipient_domain();
        let discovery = discover(&self.resolver, domain).await;
        let pinned = pins.lookup(domain, SystemTime::now());
        let authorities = match choose_endpoints(discovery, pinned) {
            Ok(authorities) => authorities,
            Err(reason) => return Ok(Attempt::UseSmtp(reason)),
        };

        let mut last = Attempt::UseSmtp(SmtpReason::NotAdvertised);
        for authority in &authorities {
            let origin = format!("https://{authority}");
            let (attempt, capabilities) = self
                .attempt(&origin, authority, envelope, message, idempotency_key)
                .await?;
            if let Some(capabilities) = capabilities {
                let max_age = capabilities.pin_max_age();
                pins.set(domain, &authorities, max_age, SystemTime::now())?;
            }
            last = attempt;
            // Only an unreachable endpoint justifies trying the next one.
            if !matches!(last, Attempt::Unreachable(_)) {
                break;
            }
        }
        Ok(last)
    }

    /// Attempts delivery to one known origin (`scheme://authority`), e.g. a
    /// pinned endpoint. `authority` is what the signature is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`SendError`] if the request cannot be built.
    pub async fn deliver_via(
        &self,
        origin: &str,
        authority: &str,
        envelope: &Envelope,
        message: &[u8],
        idempotency_key: &IdempotencyKey,
    ) -> Result<Attempt, SendError> {
        let (attempt, _) = self
            .attempt(origin, authority, envelope, message, idempotency_key)
            .await?;
        Ok(attempt)
    }

    /// One attempt, plus the capabilities document if the origin served one.
    async fn attempt(
        &self,
        origin: &str,
        authority: &str,
        envelope: &Envelope,
        message: &[u8],
        idempotency_key: &IdempotencyKey,
    ) -> Result<(Attempt, Option<Capabilities>), SendError> {
        self.check_sender(envelope)?;
        let body = encode(envelope, message)?;

        let capabilities = match self.fetch_capabilities(origin).await {
            Ok(capabilities) => capabilities,
            Err(attempt) => return Ok((attempt, None)),
        };
        if let Some(attempt) = check_limits(&capabilities, envelope, body.bytes.len()) {
            return Ok((attempt, Some(capabilities)));
        }

        let headers = sign(
            &signing::Request {
                method: "POST",
                authority,
                path: MESSAGES_PATH,
                content_type: &body.content_type,
                idempotency_key,
                body: &body.bytes,
            },
            self.identity.key(),
            self.identity.keyid(),
            SystemTime::now(),
        )?;

        let response = self
            .http
            .post(format!("{origin}{MESSAGES_PATH}"))
            .header(header::CONTENT_TYPE, &body.content_type)
            .header("idempotency-key", idempotency_key.as_str())
            .header("content-digest", headers.content_digest)
            .header("signature-input", headers.signature_input)
            .header("signature", headers.signature)
            .body(body.bytes)
            .send()
            .await;
        let attempt = match response {
            Ok(response) => classify_delivery(response).await,
            Err(error) => Attempt::Unreachable(error),
        };
        Ok((attempt, Some(capabilities)))
    }

    /// The domain this sender signs for.
    #[must_use]
    pub fn signing_domain(&self) -> &Domain {
        self.identity.keyid().domain()
    }

    fn check_sender(&self, envelope: &Envelope) -> Result<(), SendError> {
        let signing_domain = self.identity.keyid().domain();
        match envelope.from() {
            ReversePath::Mailbox(mailbox) if mailbox.domain() != signing_domain => {
                Err(SendError::SenderDomain(signing_domain.to_string()))
            }
            ReversePath::Mailbox(_) | ReversePath::Null => Ok(()),
        }
    }

    /// `Err` carries the attempt outcome when capabilities cannot be used.
    async fn fetch_capabilities(&self, origin: &str) -> Result<Capabilities, Attempt> {
        let response = self
            .http
            .get(format!("{origin}{CAPABILITIES_PATH}"))
            .send()
            .await
            .map_err(Attempt::Unreachable)?;

        if response.status() != StatusCode::OK {
            return Err(classify_failure(response).await);
        }
        response
            .json::<Capabilities>()
            .await
            .map_err(Attempt::Unreachable)
    }
}

/// The decision table of `spec/discovery.md` §3.2: a fresh record wins; without
/// one, a valid pin keeps delivery on IDMX; without either, SMTP.
fn choose_endpoints(
    discovery: Result<Discovery, DiscoveryError>,
    pinned: Option<&[String]>,
) -> Result<Vec<String>, SmtpReason> {
    match (discovery, pinned) {
        (Ok(Discovery::Supported(endpoints)), _) => {
            Ok(endpoints.iter().map(Endpoint::authority).collect())
        }
        (Ok(Discovery::Unsupported) | Err(_), Some(pinned)) => Ok(pinned.to_vec()),
        (Ok(Discovery::Unsupported), None) => Err(SmtpReason::NotAdvertised),
        (Err(error), None) => Err(SmtpReason::DiscoveryFailed(error)),
    }
}

/// Refuses locally what the receiver has announced it would refuse.
fn check_limits(
    capabilities: &Capabilities,
    envelope: &Envelope,
    body_len: usize,
) -> Option<Attempt> {
    let exceeds =
        |value: usize, limit: u64| u64::try_from(value).map_or(true, |value| value > limit);

    if !capabilities.supports_this_version() {
        Some(Attempt::UseSmtp(SmtpReason::NoCommonVersion))
    } else if exceeds(body_len, capabilities.max_message_size) {
        Some(Attempt::Rejected(Problem::new(
            ProblemKind::MessageTooLarge,
        )))
    } else if exceeds(envelope.to().len(), capabilities.max_recipients) {
        Some(Attempt::Rejected(
            Problem::new(ProblemKind::InvalidRequest).with_detail("too many recipients"),
        ))
    } else {
        None
    }
}

async fn classify_delivery(response: Response) -> Attempt {
    if response.status() != StatusCode::OK {
        return classify_failure(response).await;
    }
    // An unreadable 200 leaves the outcome unknown; the retry replays it.
    response
        .json::<DeliveryResult>()
        .await
        .map_or_else(Attempt::Unreachable, Attempt::Completed)
}

/// Classifies a non-200 response (`spec/errors.md` §2): by problem type if
/// known, else by status class.
async fn classify_failure(response: Response) -> Attempt {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|seconds| seconds.parse().ok())
        .map(Duration::from_secs);
    let problem = response.json::<Problem>().await.ok();

    let kind = problem
        .as_ref()
        .and_then(|problem| match &problem.problem_type {
            ProblemType::Known(kind) => Some(*kind),
            ProblemType::Other(_) => None,
        });
    let class = kind.map_or_else(
        || {
            if status.is_client_error() {
                FailureClass::Permanent
            } else {
                FailureClass::Temporary
            }
        },
        ProblemKind::class,
    );

    match (kind, class) {
        (Some(ProblemKind::UnsupportedVersion), _) => Attempt::UseSmtp(SmtpReason::NoCommonVersion),
        (_, FailureClass::Temporary) => Attempt::TryLater {
            // `spec/errors.md` §3: only a request-level 5xx may end in SMTP.
            fallback: if status.is_server_error() {
                SmtpFallback::AfterWindow
            } else {
                SmtpFallback::Never
            },
            problem,
            retry_after,
        },
        (_, FailureClass::Permanent) => Attempt::Rejected(problem.unwrap_or_else(|| Problem {
            problem_type: ProblemType::Other("about:blank".to_owned()),
            title: None,
            status: Some(status.as_u16()),
            detail: None,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned() -> Vec<String> {
        vec!["idmx.receiver.example:8443".to_owned()]
    }

    #[test]
    fn choose_endpoints_should_use_pin_when_record_is_gone() {
        let chosen = choose_endpoints(Ok(Discovery::Unsupported), Some(&pinned()));

        assert_eq!(chosen.ok(), Some(pinned()));
    }

    #[test]
    fn choose_endpoints_should_use_pin_when_lookup_fails() {
        let chosen = choose_endpoints(Err(DiscoveryError::AliasChainTooLong), Some(&pinned()));

        assert_eq!(chosen.ok(), Some(pinned()));
    }

    #[test]
    fn choose_endpoints_should_use_smtp_when_record_is_gone_and_no_pin() {
        let chosen = choose_endpoints(Ok(Discovery::Unsupported), None);

        assert!(matches!(chosen, Err(SmtpReason::NotAdvertised)));
    }

    #[test]
    fn choose_endpoints_should_use_smtp_when_lookup_fails_and_no_pin() {
        let chosen = choose_endpoints(Err(DiscoveryError::AliasChainTooLong), None);

        assert!(matches!(chosen, Err(SmtpReason::DiscoveryFailed(_))));
    }
}
