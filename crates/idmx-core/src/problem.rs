//! RFC 9457 problem details with the IDMX error identifiers (`spec/errors.md`).

use std::fmt;

use serde::{Deserialize, Serialize};

const TYPE_URI_PREFIX: &str = "https://idmx-project.org/problems/";

/// Whether a failure may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Retrying the same delivery cannot succeed.
    Permanent,
    /// Retrying later may succeed.
    Temporary,
}

/// The error identifiers of `spec/errors.md` §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_signature`
    InvalidSignature,
    /// `policy_rejected`
    PolicyRejected,
    /// `recipient_not_found`
    RecipientNotFound,
    /// `unsupported_version`
    UnsupportedVersion,
    /// `idempotency_conflict`
    IdempotencyConflict,
    /// `message_too_large`
    MessageTooLarge,
    /// `rate_limited`
    RateLimited,
    /// `mailbox_full`
    MailboxFull,
    /// `temporary_failure`
    TemporaryFailure,
}

impl ProblemKind {
    const ALL: [Self; 10] = [
        Self::InvalidRequest,
        Self::InvalidSignature,
        Self::PolicyRejected,
        Self::RecipientNotFound,
        Self::UnsupportedVersion,
        Self::IdempotencyConflict,
        Self::MessageTooLarge,
        Self::RateLimited,
        Self::MailboxFull,
        Self::TemporaryFailure,
    ];

    /// The identifier as written in the spec, e.g. `invalid_signature`.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidSignature => "invalid_signature",
            Self::PolicyRejected => "policy_rejected",
            Self::RecipientNotFound => "recipient_not_found",
            Self::UnsupportedVersion => "unsupported_version",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::MessageTooLarge => "message_too_large",
            Self::RateLimited => "rate_limited",
            Self::MailboxFull => "mailbox_full",
            Self::TemporaryFailure => "temporary_failure",
        }
    }

    /// HTTP status of a request-level problem response; `None` for identifiers
    /// that only occur inside per-recipient results.
    #[must_use]
    pub fn http_status(self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::InvalidSignature => Some(401),
            Self::PolicyRejected => Some(403),
            Self::UnsupportedVersion => Some(404),
            Self::IdempotencyConflict => Some(409),
            Self::MessageTooLarge => Some(413),
            Self::RateLimited => Some(429),
            Self::TemporaryFailure => Some(503),
            Self::RecipientNotFound | Self::MailboxFull => None,
        }
    }

    /// Whether the failure is permanent or temporary.
    #[must_use]
    pub fn class(self) -> FailureClass {
        match self {
            Self::RateLimited | Self::MailboxFull | Self::TemporaryFailure => {
                FailureClass::Temporary
            }
            Self::InvalidRequest
            | Self::InvalidSignature
            | Self::PolicyRejected
            | Self::RecipientNotFound
            | Self::UnsupportedVersion
            | Self::IdempotencyConflict
            | Self::MessageTooLarge => FailureClass::Permanent,
        }
    }
}

/// The `type` member of a problem document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ProblemType {
    /// An identifier defined by this version of the spec.
    Known(ProblemKind),
    /// Any other URI. Senders classify it by HTTP status class or result status.
    Other(String),
}

impl From<String> for ProblemType {
    fn from(uri: String) -> Self {
        let known = uri.strip_prefix(TYPE_URI_PREFIX).and_then(|identifier| {
            ProblemKind::ALL
                .into_iter()
                .find(|kind| kind.identifier() == identifier)
        });
        known.map_or(Self::Other(uri), Self::Known)
    }
}

impl From<ProblemType> for String {
    fn from(problem_type: ProblemType) -> Self {
        problem_type.to_string()
    }
}

impl fmt::Display for ProblemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(kind) => write!(f, "{TYPE_URI_PREFIX}{}", kind.identifier()),
            Self::Other(uri) => f.write_str(uri),
        }
    }
}

/// An RFC 9457 problem document. Unknown members are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// What went wrong.
    #[serde(rename = "type")]
    pub problem_type: ProblemType,
    /// Short human-readable summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// HTTP status, repeated for convenience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Human-readable explanation of this occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Problem {
    /// A problem of a spec-defined kind, with `status` filled in where the kind
    /// has one.
    #[must_use]
    pub fn new(kind: ProblemKind) -> Self {
        Self {
            problem_type: ProblemType::Known(kind),
            title: None,
            status: kind.http_status(),
            detail: None,
        }
    }

    /// Adds a human-readable explanation.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_should_write_type_uri_and_status() {
        let json = serde_json::to_string(&Problem::new(ProblemKind::InvalidSignature)).unwrap();

        assert_eq!(
            json,
            r#"{"type":"https://idmx-project.org/problems/invalid_signature","status":401}"#
        );
    }

    #[test]
    fn serialize_should_omit_status_for_per_recipient_kind() {
        let json = serde_json::to_string(&Problem::new(ProblemKind::MailboxFull)).unwrap();

        assert_eq!(
            json,
            r#"{"type":"https://idmx-project.org/problems/mailbox_full"}"#
        );
    }

    #[test]
    fn deserialize_should_recognize_every_known_identifier() {
        for kind in ProblemKind::ALL {
            let uri = ProblemType::Known(kind).to_string();

            assert_eq!(ProblemType::from(uri), ProblemType::Known(kind));
        }
    }

    #[test]
    fn deserialize_should_keep_unknown_type_uri() {
        let problem: Problem =
            serde_json::from_str(r#"{"type":"https://example.org/problems/custom"}"#).unwrap();

        assert_eq!(
            problem.problem_type,
            ProblemType::Other("https://example.org/problems/custom".to_owned())
        );
    }

    #[test]
    fn deserialize_should_ignore_unknown_members() {
        let json = r#"{"type":"https://idmx-project.org/problems/rate_limited","instance":"/x"}"#;

        let result = serde_json::from_str::<Problem>(json);

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn class_should_be_temporary_for_rate_limited() {
        assert_eq!(ProblemKind::RateLimited.class(), FailureClass::Temporary);
    }

    #[test]
    fn class_should_be_permanent_for_idempotency_conflict() {
        assert_eq!(
            ProblemKind::IdempotencyConflict.class(),
            FailureClass::Permanent
        );
    }
}
