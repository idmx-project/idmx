//! Per-recipient delivery results (`spec/delivery.md` §5.2).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mailbox::Mailbox;
use crate::problem::{Problem, ProblemKind};

/// Error from decoding a [`RecipientResult`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("result for `{recipient}` has status `{status}` but no problem")]
pub struct MissingProblemError {
    recipient: Mailbox,
    status: String,
}

/// What happened to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The receiver took responsibility for the message.
    Accepted,
    /// Permanent failure: bounce; never retry, never fall back to SMTP.
    Rejected {
        /// Why.
        problem: Problem,
    },
    /// Temporary failure: retry as a new delivery.
    Deferred {
        /// Why.
        problem: Problem,
        /// Receiver's hint for when to retry.
        retry_after: Option<Duration>,
    },
}

/// The outcome for one envelope recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RecipientResultWire", into = "RecipientResultWire")]
pub struct RecipientResult {
    /// The recipient, as listed in the envelope.
    pub recipient: Mailbox,
    /// What happened.
    pub outcome: Outcome,
}

/// The response body of an acceptable `POST /v1/messages`: one result per
/// envelope recipient, in envelope order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryResult {
    /// The results.
    pub results: Vec<RecipientResult>,
}

#[derive(Serialize, Deserialize)]
struct RecipientResultWire {
    recipient: Mailbox,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    problem: Option<Problem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

impl TryFrom<RecipientResultWire> for RecipientResult {
    type Error = MissingProblemError;

    fn try_from(wire: RecipientResultWire) -> Result<Self, Self::Error> {
        let RecipientResultWire {
            recipient,
            status,
            problem,
            retry_after,
        } = wire;
        let retry_after = retry_after.map(Duration::from_secs);

        let outcome = match (status.as_str(), problem) {
            ("accepted", _) => Outcome::Accepted,
            ("rejected", Some(problem)) => Outcome::Rejected { problem },
            ("deferred", Some(problem)) => Outcome::Deferred {
                problem,
                retry_after,
            },
            ("rejected" | "deferred", None) => {
                return Err(MissingProblemError { recipient, status });
            }
            // `spec/delivery.md` §5.2: an unknown status is handled as deferred.
            (_, problem) => Outcome::Deferred {
                problem: problem.unwrap_or_else(|| Problem::new(ProblemKind::TemporaryFailure)),
                retry_after,
            },
        };
        Ok(Self { recipient, outcome })
    }
}

impl From<RecipientResult> for RecipientResultWire {
    fn from(result: RecipientResult) -> Self {
        let (status, problem, retry_after) = match result.outcome {
            Outcome::Accepted => ("accepted", None, None),
            Outcome::Rejected { problem } => ("rejected", Some(problem), None),
            Outcome::Deferred {
                problem,
                retry_after,
            } => ("deferred", Some(problem), retry_after),
        };
        Self {
            recipient: result.recipient,
            status: status.to_owned(),
            problem,
            retry_after: retry_after.map(|duration| duration.as_secs()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(json: &str) -> Result<RecipientResult, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn deserialize_should_read_accepted() {
        let result = decode(r#"{"recipient":"bob@receiver.example","status":"accepted"}"#);

        assert_eq!(result.unwrap().outcome, Outcome::Accepted);
    }

    #[test]
    fn deserialize_should_read_deferred_with_retry_after() {
        let result = decode(
            r#"{"recipient":"bob@receiver.example","status":"deferred","retry_after":3600,
                "problem":{"type":"https://idmx-project.org/problems/mailbox_full"}}"#,
        );

        assert_eq!(
            result.unwrap().outcome,
            Outcome::Deferred {
                problem: Problem::new(ProblemKind::MailboxFull),
                retry_after: Some(Duration::from_hours(1)),
            }
        );
    }

    #[test]
    fn deserialize_should_fail_when_rejected_without_problem() {
        let result = decode(r#"{"recipient":"bob@receiver.example","status":"rejected"}"#);

        assert!(result.is_err(), "unexpected: {result:?}");
    }

    #[test]
    fn deserialize_should_treat_unknown_status_as_deferred() {
        let result = decode(r#"{"recipient":"bob@receiver.example","status":"quarantined"}"#);

        assert!(
            matches!(
                result,
                Ok(RecipientResult {
                    outcome: Outcome::Deferred { .. },
                    ..
                })
            ),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn serialize_should_round_trip_rejected() {
        let original = RecipientResult {
            recipient: "nobody@receiver.example".parse().unwrap(),
            outcome: Outcome::Rejected {
                problem: Problem::new(ProblemKind::RecipientNotFound),
            },
        };

        let json = serde_json::to_string(&original).unwrap();

        assert_eq!(decode(&json).unwrap(), original);
    }
}
