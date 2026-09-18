//! Checks that need signed deliveries (`spec/signing.md`, `spec/delivery.md`).
//!
//! They need a key the receiver can resolve and a mailbox that exists, and
//! they deliver real probe messages to that mailbox.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use idmx_core::body::{EncodedBody, encode};
use idmx_core::envelope::{Envelope, ReversePath};
use idmx_core::idempotency::IdempotencyKey;
use idmx_core::key::KeyId;
use idmx_core::mailbox::Mailbox;
use idmx_core::signing::{self, sign};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{Map, Value};

use crate::report::{Check, Level, Outcome};
use crate::{Origin, expect_problem};

const MESSAGE: &[u8] = b"Subject: IDMX conformance probe\r\n\r\nSent by idmx-conformance.\r\n";
/// Far outside the ±5 min window of `signing.md` §3.
const CLOCK_OFFSET: Duration = Duration::from_mins(10);
/// The over-size check uploads `max_message_size` bytes; skip it above this.
const LARGEST_UPLOAD: u64 = 64 * 1024 * 1024;
const FOREIGN_MAILBOX: &str = "probe@conformance.invalid";

/// What the signed checks deliver with and to.
pub struct DeliveryProbe {
    key: SigningKey,
    keyid: KeyId,
    recipient: Mailbox,
}

/// Why a request could not be built; reported as a skipped check.
#[derive(Debug, thiserror::Error)]
enum BuildError {
    #[error("cannot build an address: {0}")]
    Address(String),
    #[error("cannot build the request: {0}")]
    Request(String),
}

/// One request, signed. `sent_body` differs from `signed.bytes` only when a
/// check tampers with the content after signing.
struct Delivery {
    signed: EncodedBody,
    idempotency_key: IdempotencyKey,
    authority: String,
    created: SystemTime,
    sent_body: Option<Vec<u8>>,
}

impl DeliveryProbe {
    /// `keyid` must be published in DNS with the public half of `key`;
    /// `recipient` must be a mailbox the receiver accepts mail for.
    #[must_use]
    pub fn new(key: SigningKey, keyid: KeyId, recipient: Mailbox) -> Self {
        Self {
            key,
            keyid,
            recipient,
        }
    }

    pub(crate) async fn run(&self, http: &Client, origin: &Origin) -> Vec<Check> {
        vec![
            self.tampered_body(http, origin).await,
            self.shifted_clock(http, origin, "SIG-03", false).await,
            self.shifted_clock(http, origin, "SIG-04", true).await,
            self.other_authority(http, origin).await,
            self.foreign_sender(http, origin).await,
            self.malformed_body(http, origin).await,
            self.foreign_recipient(http, origin).await,
            self.oversize(http, origin).await,
            self.accepted(http, origin).await,
            self.replay(http, origin).await,
            self.conflict(http, origin).await,
        ]
        .into_iter()
        .chain(self.results(http, origin).await)
        .collect()
    }

    fn sender(&self) -> Result<ReversePath, BuildError> {
        format!("idmx-conformance@{}", self.keyid.domain())
            .parse()
            .map(ReversePath::Mailbox)
            .map_err(|_| BuildError::Address(self.keyid.domain().to_string()))
    }

    fn unknown_recipient(&self) -> Result<Mailbox, BuildError> {
        format!("idmx-conformance-no-such-user@{}", self.recipient.domain())
            .parse()
            .map_err(|_| BuildError::Address(self.recipient.domain().to_string()))
    }

    /// A well-formed delivery to the probe recipient, signed now.
    fn delivery(&self, origin: &Origin, label: &str) -> Result<Delivery, BuildError> {
        build_delivery(origin, label, self.sender()?, vec![self.recipient.clone()])
    }

    fn request(
        &self,
        http: &Client,
        origin: &Origin,
        delivery: Delivery,
    ) -> Result<RequestBuilder, BuildError> {
        let headers = sign(
            &signing::Request {
                method: "POST",
                authority: &delivery.authority,
                path: "/v1/messages",
                content_type: &delivery.signed.content_type,
                idempotency_key: &delivery.idempotency_key,
                body: &delivery.signed.bytes,
            },
            &self.key,
            &self.keyid,
            delivery.created,
        )
        .map_err(|error| BuildError::Request(error.to_string()))?;

        Ok(http
            .post(origin.url("/v1/messages"))
            .header(CONTENT_TYPE, &delivery.signed.content_type)
            .header("idempotency-key", delivery.idempotency_key.as_str())
            .header("content-digest", headers.content_digest)
            .header("signature-input", headers.signature_input)
            .header("signature", headers.signature)
            .body(delivery.sent_body.unwrap_or(delivery.signed.bytes)))
    }

    /// Builds the request and expects a problem answer.
    async fn expect(
        &self,
        http: &Client,
        origin: &Origin,
        delivery: Result<Delivery, BuildError>,
        status: StatusCode,
        kind: &str,
    ) -> Outcome {
        match delivery.and_then(|delivery| self.request(http, origin, delivery)) {
            Ok(request) => expect_problem(request, status, kind).await,
            Err(error) => Outcome::Skipped(error.to_string()),
        }
    }

    async fn tampered_body(&self, http: &Client, origin: &Origin) -> Check {
        let delivery = self.delivery(origin, "digest").map(|mut delivery| {
            // Same length, other content: only the digest can catch it.
            let mut body = delivery.signed.bytes.clone();
            if let Some(last) = body.iter_mut().rev().find(|byte| **byte == b'.') {
                *last = b'!';
            }
            delivery.sent_body = Some(body);
            delivery
        });
        Check {
            id: "SIG-02",
            spec: "signing.md §2.2",
            level: Level::Must,
            requirement: "content that does not match Content-Digest answers 401 invalid_signature",
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                )
                .await,
        }
    }

    async fn shifted_clock(
        &self,
        http: &Client,
        origin: &Origin,
        id: &'static str,
        future: bool,
    ) -> Check {
        let delivery = self.delivery(origin, id).map(|mut delivery| {
            delivery.created = if future {
                delivery.created + CLOCK_OFFSET
            } else {
                delivery.created - CLOCK_OFFSET
            };
            delivery
        });
        Check {
            id,
            spec: "signing.md §3",
            level: Level::Must,
            requirement: if future {
                "created 10 minutes in the future answers 401 invalid_signature"
            } else {
                "created 10 minutes in the past answers 401 invalid_signature"
            },
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                )
                .await,
        }
    }

    async fn other_authority(&self, http: &Client, origin: &Origin) -> Check {
        let delivery = self.delivery(origin, "authority").map(|mut delivery| {
            "idmx.conformance.invalid".clone_into(&mut delivery.authority);
            delivery
        });
        Check {
            id: "SIG-05",
            spec: "signing.md §2.5",
            level: Level::Must,
            requirement: "a signature made for another authority answers 401 invalid_signature",
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                )
                .await,
        }
    }

    async fn foreign_sender(&self, http: &Client, origin: &Origin) -> Check {
        let delivery = foreign_mailbox().and_then(|from| {
            build_delivery(
                origin,
                "sender",
                ReversePath::Mailbox(from),
                vec![self.recipient.clone()],
            )
        });
        Check {
            id: "SIG-06",
            spec: "signing.md §2.5",
            level: Level::Must,
            requirement: "an envelope from outside the signing domain answers 401 invalid_signature",
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::UNAUTHORIZED,
                    "invalid_signature",
                )
                .await,
        }
    }

    async fn malformed_body(&self, http: &Client, origin: &Origin) -> Check {
        let delivery = self.delivery(origin, "layout").map(|mut delivery| {
            delivery.signed = EncodedBody {
                content_type: "multipart/mixed; boundary=idmx-conformance".to_owned(),
                bytes: b"--idmx-conformance\r\nContent-Type: application/json\r\n\r\n{}\r\n\
                    --idmx-conformance--\r\n"
                    .to_vec(),
            };
            delivery
        });
        Check {
            id: "REQ-01",
            spec: "delivery.md §2",
            level: Level::Must,
            requirement: "a signed body without the two-part layout answers 400 invalid_request",
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        }
    }

    async fn foreign_recipient(&self, http: &Client, origin: &Origin) -> Check {
        let delivery = foreign_mailbox().and_then(|to| {
            let from = self.sender()?;
            build_delivery(origin, "recipient", from, vec![to])
        });
        Check {
            id: "REQ-02",
            spec: "delivery.md §3",
            level: Level::Must,
            requirement: "recipients of a domain the receiver does not serve answer 403 policy_rejected",
            outcome: self
                .expect(
                    http,
                    origin,
                    delivery,
                    StatusCode::FORBIDDEN,
                    "policy_rejected",
                )
                .await,
        }
    }

    async fn oversize(&self, http: &Client, origin: &Origin) -> Check {
        let check = |outcome| Check {
            id: "REQ-03",
            spec: "delivery.md §6",
            level: Level::Must,
            requirement: "a body above max_message_size answers 413 message_too_large",
            outcome,
        };
        let limit = match advertised_limit(http, origin).await {
            Ok(limit) if limit <= LARGEST_UPLOAD => limit,
            Ok(limit) => {
                return check(Outcome::Skipped(format!(
                    "max_message_size {limit} is too large to probe"
                )));
            }
            Err(reason) => return check(Outcome::Skipped(reason)),
        };
        let Ok(padding) = usize::try_from(limit) else {
            return check(Outcome::Skipped("limit exceeds this platform".to_owned()));
        };

        let mut message = MESSAGE.to_vec();
        message.resize(message.len() + padding, b'a');
        let delivery = self.delivery(origin, "size").and_then(|mut delivery| {
            let envelope = Envelope::new(self.sender()?, vec![self.recipient.clone()])
                .map_err(|error| BuildError::Request(error.to_string()))?;
            delivery.signed = encode(&envelope, &message)
                .map_err(|error| BuildError::Request(error.to_string()))?;
            Ok(delivery)
        });
        check(
            self.expect(
                http,
                origin,
                delivery,
                StatusCode::PAYLOAD_TOO_LARGE,
                "message_too_large",
            )
            .await,
        )
    }

    async fn accepted(&self, http: &Client, origin: &Origin) -> Check {
        let outcome = match self
            .deliver(http, origin, self.delivery(origin, "accept"))
            .await
        {
            Ok((StatusCode::OK, body)) => match statuses(&body) {
                Some(results)
                    if results == [(self.recipient.to_string(), "accepted".to_owned())] =>
                {
                    Outcome::Pass
                }
                Some(results) => Outcome::Fail(format!("results {results:?}")),
                None => Outcome::Fail("no results array".to_owned()),
            },
            Ok((status, _)) => Outcome::Fail(format!("status {status}")),
            Err(outcome) => outcome,
        };
        Check {
            id: "DLV-01",
            spec: "delivery.md §5.2",
            level: Level::Must,
            requirement: "a valid delivery answers 200 with one accepted result for the recipient",
            outcome,
        }
    }

    async fn replay(&self, http: &Client, origin: &Origin) -> Check {
        let first = self.delivery(origin, "replay");
        let second = first.as_ref().ok().map(|first| Delivery {
            signed: first.signed.clone(),
            idempotency_key: first.idempotency_key.clone(),
            authority: first.authority.clone(),
            // A retry re-signs with a fresh timestamp (`signing.md` §3).
            created: first.created + Duration::from_secs(1),
            sent_body: None,
        });
        let outcome = match (self.deliver(http, origin, first).await, second) {
            // Anything else proves nothing: only a 200 answer is recorded.
            (Ok((status, body)), _) if status != StatusCode::OK || statuses(&body).is_none() => {
                Outcome::Skipped(format!("first delivery answered {status} without results"))
            }
            (Ok(original), Some(second)) => match self.deliver(http, origin, Ok(second)).await {
                Ok(repeated) if repeated == original => Outcome::Pass,
                Ok((status, _)) => Outcome::Fail(format!(
                    "first answer {}, replay answer {status} or another body",
                    original.0
                )),
                Err(outcome) => outcome,
            },
            (Err(outcome), _) => outcome,
            (Ok(_), None) => Outcome::Skipped("no request".to_owned()),
        };
        Check {
            id: "IDM-01",
            spec: "delivery.md §4",
            level: Level::Must,
            requirement: "the same key with the same content returns the original response",
            outcome,
        }
    }

    async fn conflict(&self, http: &Client, origin: &Origin) -> Check {
        let first = self.delivery(origin, "conflict");
        let second = first.as_ref().ok().and_then(|first| {
            let envelope = Envelope::new(self.sender().ok()?, vec![self.recipient.clone()]).ok()?;
            Some(Delivery {
                signed: encode(&envelope, b"Subject: other content\r\n\r\n").ok()?,
                idempotency_key: first.idempotency_key.clone(),
                authority: first.authority.clone(),
                created: first.created,
                sent_body: None,
            })
        });
        let outcome = match (self.deliver(http, origin, first).await, second) {
            (Ok((StatusCode::OK, _)), Some(second)) => {
                self.expect(
                    http,
                    origin,
                    Ok(second),
                    StatusCode::CONFLICT,
                    "idempotency_conflict",
                )
                .await
            }
            (Ok((status, _)), _) => Outcome::Skipped(format!("first delivery answered {status}")),
            (Err(outcome), _) => outcome,
        };
        Check {
            id: "IDM-02",
            spec: "delivery.md §4",
            level: Level::Must,
            requirement: "the same key with other content answers 409 idempotency_conflict",
            outcome,
        }
    }

    /// One delivery to an unknown and the known recipient: result order, and
    /// synchronous recipient validation.
    async fn results(&self, http: &Client, origin: &Origin) -> [Check; 2] {
        let delivery = self.unknown_recipient().and_then(|unknown| {
            let from = self.sender()?;
            build_delivery(origin, "order", from, vec![unknown, self.recipient.clone()])
        });
        let results = match self.deliver(http, origin, delivery).await {
            Ok((StatusCode::OK, body)) => {
                statuses(&body).ok_or_else(|| Outcome::Fail("no results array".to_owned()))
            }
            Ok((status, _)) => Err(Outcome::Fail(format!("status {status}"))),
            Err(outcome) => Err(outcome),
        };

        let recipient = self.recipient.to_string();
        let ordered = |results: &[(String, String)]| {
            matches!(results, [(first, _), (second, _)]
                if first.starts_with("idmx-conformance-no-such-user@") && *second == recipient)
        };
        let order = match &results {
            Ok(results) if ordered(results) => Outcome::Pass,
            Ok(results) => Outcome::Fail(format!("results {results:?}")),
            Err(outcome) => outcome.clone(),
        };
        let validation = match &results {
            Ok(results) => match results.first() {
                Some((_, status)) if status == "rejected" => Outcome::Pass,
                Some((_, status)) => Outcome::Fail(format!("unknown recipient was {status}")),
                None => Outcome::Fail("no results".to_owned()),
            },
            Err(outcome) => outcome.clone(),
        };
        [
            Check {
                id: "DLV-02",
                spec: "delivery.md §5.2",
                level: Level::Must,
                requirement: "a 200 answer has one result per recipient, in the order of `to`",
                outcome: order,
            },
            Check {
                id: "DLV-03",
                spec: "delivery.md §5.2",
                level: Level::Should,
                requirement: "an unknown recipient is rejected synchronously",
                outcome: validation,
            },
        ]
    }

    /// Sends a delivery and returns status and body; `Err` is the outcome to
    /// report when there is no HTTP answer.
    async fn deliver(
        &self,
        http: &Client,
        origin: &Origin,
        delivery: Result<Delivery, BuildError>,
    ) -> Result<(StatusCode, Vec<u8>), Outcome> {
        let request = delivery
            .and_then(|delivery| self.request(http, origin, delivery))
            .map_err(|error| Outcome::Skipped(error.to_string()))?;
        let response = request
            .send()
            .await
            .map_err(|error| Outcome::Fail(error.to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| Outcome::Fail(error.to_string()))?;
        Ok((status, body.to_vec()))
    }
}

fn build_delivery(
    origin: &Origin,
    label: &str,
    from: ReversePath,
    to: Vec<Mailbox>,
) -> Result<Delivery, BuildError> {
    let envelope =
        Envelope::new(from, to).map_err(|error| BuildError::Request(error.to_string()))?;
    let signed =
        encode(&envelope, MESSAGE).map_err(|error| BuildError::Request(error.to_string()))?;
    Ok(Delivery {
        signed,
        idempotency_key: fresh_key(label)?,
        authority: origin.authority(),
        created: SystemTime::now(),
        sent_body: None,
    })
}

fn foreign_mailbox() -> Result<Mailbox, BuildError> {
    FOREIGN_MAILBOX
        .parse()
        .map_err(|_| BuildError::Address(FOREIGN_MAILBOX.to_owned()))
}

/// Unique per run and per check, so reruns never hit recorded keys.
fn fresh_key(label: &str) -> Result<IdempotencyKey, BuildError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("idmx-conformance-{nanos}-{label}")
        .parse()
        .map_err(|_| BuildError::Request(format!("idempotency key for {label}")))
}

async fn advertised_limit(http: &Client, origin: &Origin) -> Result<u64, String> {
    let response = http
        .get(origin.url("/v1/capabilities"))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let document = response
        .json::<Map<String, Value>>()
        .await
        .map_err(|error| error.to_string())?;
    document
        .get("max_message_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| "capabilities has no max_message_size".to_owned())
}

/// `(recipient, status)` of every result, in order.
fn statuses(body: &[u8]) -> Option<Vec<(String, String)>> {
    let document: Value = serde_json::from_slice(body).ok()?;
    document
        .get("results")?
        .as_array()?
        .iter()
        .map(|result| {
            Some((
                result.get("recipient")?.as_str()?.to_owned(),
                result.get("status")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}
