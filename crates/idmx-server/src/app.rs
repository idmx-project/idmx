//! The HTTP surface: `GET /v1/capabilities` and `POST /v1/messages`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use idmx_core::body::decode;
use idmx_core::capabilities::{Capabilities, VERSION};
use idmx_core::envelope::Envelope;
use idmx_core::idempotency::IdempotencyKey;
use idmx_core::mailbox::Mailbox;
use idmx_core::problem::{Problem, ProblemKind};
use idmx_core::result::{DeliveryResult, Outcome, RecipientResult};
use idmx_core::signing::{
    self, SignatureHeaders, UnverifiedSignature, VerifiedSignature, content_digest,
};

use crate::config::Config;
use crate::error::{DeliveryError, problem_response};
use crate::idempotency::{Admission, IdempotencyStore};
use crate::keys::KeySource;
use crate::maildir;
use crate::trace::{Trace, add_trace_headers};

/// Everything the handlers share.
pub struct App {
    /// Validated configuration.
    pub config: Config,
    /// Source of sender public keys.
    pub keys: Box<dyn KeySource>,
    /// Completed deliveries.
    pub idempotency: IdempotencyStore,
}

/// Builds the router for `app`.
pub fn router(app: App) -> Router {
    Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/messages", post(deliver))
        .fallback(unknown_path)
        .with_state(Arc::new(app))
}

async fn capabilities(State(app): State<Arc<App>>) -> Response {
    let body = Capabilities {
        versions: vec![VERSION.to_owned()],
        max_message_size: app.config.max_message_size as u64,
        max_recipients: app.config.max_recipients as u64,
        discovery_pin_max_age: app.config.discovery_pin_max_age,
        abuse_contact: app.config.abuse_contact.clone(),
    };
    let mut response = axum::Json(body).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

/// Any other major version is `unsupported_version`; anything else a plain 404.
async fn unknown_path(uri: Uri) -> Response {
    let first_segment = uri.path().trim_start_matches('/').split('/').next();
    let is_version = first_segment
        .and_then(|segment| segment.strip_prefix('v'))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));

    if is_version && first_segment != Some("v1") {
        problem_response(&Problem::new(ProblemKind::UnsupportedVersion))
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn deliver(State(app): State<Arc<App>>, request: Request) -> Result<Response, DeliveryError> {
    let now = SystemTime::now();
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    let authority = request_authority(&parts.uri, headers)?;
    if authority != app.config.authority {
        return Err(DeliveryError::Authority(authority));
    }
    let idempotency_key: IdempotencyKey = text_header(headers, "idempotency-key")?.parse()?;
    let content_type = text_header(headers, "content-type")?;
    let signature_headers = SignatureHeaders {
        content_digest: signature_header(headers, "content-digest")?.to_owned(),
        signature_input: signature_header(headers, "signature-input")?.to_owned(),
        signature: signature_header(headers, "signature")?.to_owned(),
    };
    let body = read_body(body, headers, app.config.max_message_size).await?;

    let signed_request = signing::Request {
        method: parts.method.as_str(),
        authority: &authority,
        path: parts.uri.path(),
        content_type,
        idempotency_key: &idempotency_key,
        body: &body,
    };
    let unverified = UnverifiedSignature::parse(&signed_request, &signature_headers, now)?;
    let key_record = app.keys.fetch(unverified.keyid()).await?;
    let signature = unverified.verify(&key_record)?;

    let decoded = decode(content_type, &body)?;
    signature.check_sender(decoded.envelope.from())?;
    check_envelope(&app.config, &decoded.envelope)?;

    let digest = content_digest(&body);
    let reservation =
        match app
            .idempotency
            .admit(signature.signing_domain(), &idempotency_key, &digest, now)
        {
            Admission::Fresh(reservation) => reservation,
            Admission::Replay(response) => return Ok(json_response(response)),
            Admission::Conflict => return Err(DeliveryError::IdempotencyConflict),
            Admission::InFlight => return Err(DeliveryError::InFlight),
        };

    let delivery = Delivery {
        app: &app,
        signature: &signature,
        idempotency_key: &idempotency_key,
        envelope: &decoded.envelope,
        received_at: now,
    };
    let result = delivery.run(decoded.message).await;
    let response = serde_json::to_string(&result)
        .map_err(|error| DeliveryError::Storage(std::io::Error::other(error)))?;
    reservation
        .complete(&response)
        .map_err(DeliveryError::Storage)?;
    Ok(json_response(response))
}

/// `@authority` of the request: the HTTP/2 `:authority`, else `Host`; lower
/// case, without the default port.
fn request_authority(uri: &Uri, headers: &HeaderMap) -> Result<String, DeliveryError> {
    let authority = match uri.authority() {
        Some(authority) => authority.as_str(),
        None => text_header(headers, "host")?,
    };
    let authority = authority.to_ascii_lowercase();
    Ok(authority
        .strip_suffix(":443")
        .map_or(authority.clone(), str::to_owned))
}

fn text_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, DeliveryError> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().map_err(|_| DeliveryError::Header(name)),
        _ => Err(DeliveryError::Header(name)),
    }
}

/// Like [`text_header`], for the headers without which a request is unsigned.
fn signature_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, DeliveryError> {
    text_header(headers, name).map_err(|_| DeliveryError::SignatureHeader(name))
}

async fn read_body(
    body: Body,
    headers: &HeaderMap,
    max_message_size: usize,
) -> Result<axum::body::Bytes, DeliveryError> {
    let declared: usize = text_header(headers, "content-length")?
        .parse()
        .map_err(|_| DeliveryError::Header("content-length"))?;
    if declared > max_message_size {
        return Err(DeliveryError::TooLarge(max_message_size));
    }
    let body = axum::body::to_bytes(body, max_message_size)
        .await
        .map_err(|_| DeliveryError::BodyRead)?;
    if body.len() == declared {
        Ok(body)
    } else {
        Err(DeliveryError::ContentLength)
    }
}

fn check_envelope(config: &Config, envelope: &Envelope) -> Result<(), DeliveryError> {
    if envelope.recipient_domain() != &config.domain {
        return Err(DeliveryError::ForeignDomain(
            envelope.recipient_domain().to_string(),
        ));
    }
    if envelope.to().len() > config.max_recipients {
        return Err(DeliveryError::TooManyRecipients(config.max_recipients));
    }
    Ok(())
}

fn json_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// One admitted delivery, fanned out to its recipients.
struct Delivery<'a> {
    app: &'a App,
    signature: &'a VerifiedSignature,
    idempotency_key: &'a IdempotencyKey,
    envelope: &'a Envelope,
    received_at: SystemTime,
}

impl Delivery<'_> {
    async fn run(&self, message: &[u8]) -> DeliveryResult {
        let recipients = self.envelope.to();
        let sole_recipient = match recipients {
            [only] => Some(only),
            _ => None,
        };
        let message = add_trace_headers(
            message,
            &Trace {
                signature: self.signature,
                hostname: self.app.config.hostname(),
                idempotency_key: self.idempotency_key,
                sole_recipient,
                received_at: self.received_at,
            },
        );

        let mut results = Vec::with_capacity(recipients.len());
        for (index, recipient) in recipients.iter().enumerate() {
            results.push(RecipientResult {
                recipient: recipient.clone(),
                outcome: self.deliver_to(recipient, index, &message).await,
            });
        }
        DeliveryResult { results }
    }

    async fn deliver_to(&self, recipient: &Mailbox, index: usize, message: &[u8]) -> Outcome {
        let Some(maildir_name) = self.app.config.mailboxes.get(recipient) else {
            return Outcome::Rejected {
                problem: Problem::new(ProblemKind::RecipientNotFound),
            };
        };
        let seconds = self
            .received_at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        // Every part is validated to be free of path separators.
        let unique_name = format!("{seconds}.{}.{index}", self.idempotency_key);
        let maildir = self.app.config.mail_root().join(maildir_name);

        match maildir::deliver(&maildir, &unique_name, message).await {
            Ok(path) => {
                tracing::info!(%recipient, path = %path.display(), "delivered");
                Outcome::Accepted
            }
            Err(error) => {
                tracing::error!(%recipient, %error, "local delivery failed");
                Outcome::Deferred {
                    problem: Problem::new(ProblemKind::TemporaryFailure),
                    retry_after: None,
                }
            }
        }
    }
}
