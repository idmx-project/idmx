//! Request-level failures and their mapping to problem responses
//! (`spec/errors.md` §2).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use idmx_core::body::BodyError;
use idmx_core::discovery::KeyLookupError;
use idmx_core::idempotency::IdempotencyKeyError;
use idmx_core::problem::{Problem, ProblemKind};
use idmx_core::signing::VerifyError;

/// Seconds a sender is asked to wait after a temporary failure.
const RETRY_AFTER_SECONDS: &str = "60";

/// Why a `POST /v1/messages` request was refused as a whole.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// A required header is missing, repeated, or not text.
    #[error("header `{0}` is missing or malformed")]
    Header(&'static str),
    /// `Idempotency-Key` does not have the required form.
    #[error(transparent)]
    IdempotencyKey(#[from] IdempotencyKeyError),
    /// `Content-Length` disagrees with the received content.
    #[error("content-length does not match the received content")]
    ContentLength,
    /// The body exceeds `max_message_size`.
    #[error("message exceeds the maximum size of {0} bytes")]
    TooLarge(usize),
    /// The body could not be read from the connection.
    #[error("request body could not be read")]
    BodyRead,
    /// The request is addressed to an authority this receiver does not serve.
    #[error("request authority `{0}` is not served here")]
    Authority(String),
    /// The signature is missing, malformed, or wrong.
    #[error(transparent)]
    Signature(#[from] VerifyError),
    /// The sender's key could not be obtained.
    #[error(transparent)]
    KeyLookup(#[from] KeyLookupError),
    /// The body is not a valid two-part delivery.
    #[error(transparent)]
    Body(#[from] BodyError),
    /// The envelope lists more recipients than advertised.
    #[error("envelope has more than {0} recipients")]
    TooManyRecipients(usize),
    /// The recipients are not in the domain this receiver serves.
    #[error("this receiver is not responsible for `{0}`")]
    ForeignDomain(String),
    /// The idempotency key was already used for different content.
    #[error("idempotency key was already used with different content")]
    IdempotencyConflict,
    /// The same delivery is being processed by a concurrent request.
    #[error("a request with this idempotency key is still being processed")]
    InFlight,
    /// The response could not be recorded durably.
    #[error("delivery state could not be stored")]
    Storage(#[source] std::io::Error),
}

impl DeliveryError {
    /// The problem identifier this failure is reported as.
    #[must_use]
    pub fn kind(&self) -> ProblemKind {
        match self {
            Self::Header(_)
            | Self::IdempotencyKey(_)
            | Self::ContentLength
            | Self::Body(_)
            | Self::TooManyRecipients(_) => ProblemKind::InvalidRequest,
            Self::TooLarge(_) => ProblemKind::MessageTooLarge,
            Self::KeyLookup(error) if error.is_temporary() => ProblemKind::TemporaryFailure,
            Self::Authority(_) | Self::Signature(_) | Self::KeyLookup(_) => {
                ProblemKind::InvalidSignature
            }
            Self::ForeignDomain(_) => ProblemKind::PolicyRejected,
            Self::IdempotencyConflict => ProblemKind::IdempotencyConflict,
            Self::BodyRead | Self::InFlight | Self::Storage(_) => ProblemKind::TemporaryFailure,
        }
    }
}

impl IntoResponse for DeliveryError {
    fn into_response(self) -> Response {
        tracing::warn!(error = %self, kind = self.kind().identifier(), "delivery refused");
        problem_response(&Problem::new(self.kind()).with_detail(self.to_string()))
    }
}

/// Renders `problem` as an `application/problem+json` response.
#[must_use]
pub fn problem_response(problem: &Problem) -> Response {
    let status = problem
        .status
        .and_then(|status| StatusCode::from_u16(status).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_string(problem).unwrap_or_else(|_| "{}".to_owned());

    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECONDS),
        );
    }
    response
}
