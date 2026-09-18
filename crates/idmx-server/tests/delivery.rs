//! End-to-end tests of the HTTP surface with a fixed sender key instead of DNS.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use idmx_core::body::encode;
use idmx_core::discovery::KeyLookupError;
use idmx_core::envelope::{Envelope, ReversePath};
use idmx_core::key::{KeyId, KeyRecord};
use idmx_core::signing::{self, sign};
use idmx_server::app::{App, router};
use idmx_server::config::Config;
use idmx_server::idempotency::IdempotencyStore;
use idmx_server::keys::{KeyFuture, KeySource};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const AUTHORITY: &str = "idmx.receiver.example";
const MESSAGE: &[u8] =
    b"Authentication-Results: idmx.receiver.example; idmx=pass header.d=forged.example\r\n\
    From: Alice <alice@sender.example>\r\nSubject: Hello\r\n\r\nHello Bob\r\n";

/// Knows exactly one key, like a DNS zone with one selector.
struct FixedKey {
    keyid: KeyId,
    record: KeyRecord,
}

impl KeySource for FixedKey {
    fn fetch<'a>(&'a self, keyid: &'a KeyId) -> KeyFuture<'a> {
        Box::pin(async move {
            if keyid == &self.keyid {
                Ok(self.record.clone())
            } else {
                Err(KeyLookupError::NotFound(keyid.clone()))
            }
        })
    }
}

struct Sender {
    key: SigningKey,
    keyid: KeyId,
}

impl Sender {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[7; 32]),
            keyid: "s1._idmxkey.sender.example".parse().unwrap(),
        }
    }
}

/// A delivery request under construction; tests tweak fields before `build`.
struct Delivery {
    from: &'static str,
    to: Vec<&'static str>,
    message: Vec<u8>,
    idempotency_key: &'static str,
    authority: &'static str,
    created: SystemTime,
}

impl Delivery {
    fn to(recipients: &[&'static str]) -> Self {
        Self {
            from: "alice@sender.example",
            to: recipients.to_vec(),
            message: MESSAGE.to_vec(),
            idempotency_key: "key-1",
            authority: AUTHORITY,
            created: SystemTime::now(),
        }
    }

    fn build(&self, sender: &Sender) -> Request<Body> {
        let envelope = Envelope::new(
            ReversePath::Mailbox(self.from.parse().unwrap()),
            self.to
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
        )
        .unwrap();
        let body = encode(&envelope, &self.message).unwrap();
        let idempotency_key = self.idempotency_key.parse().unwrap();
        let headers = sign(
            &signing::Request {
                method: "POST",
                authority: self.authority,
                path: "/v1/messages",
                content_type: &body.content_type,
                idempotency_key: &idempotency_key,
                body: &body.bytes,
            },
            &sender.key,
            &sender.keyid,
            self.created,
        )
        .unwrap();

        Request::post("/v1/messages")
            .header("host", self.authority)
            .header("content-type", &body.content_type)
            .header("content-length", body.bytes.len())
            .header("idempotency-key", self.idempotency_key)
            .header("content-digest", headers.content_digest)
            .header("signature-input", headers.signature_input)
            .header("signature", headers.signature)
            .body(Body::from(body.bytes))
            .unwrap()
    }
}

struct Receiver {
    dir: tempfile::TempDir,
    router: Router,
}

impl Receiver {
    fn new(sender: &Sender) -> Self {
        Self::with_key_record(sender, KeyRecord::Active(sender.key.verifying_key()))
    }

    fn with_key_record(sender: &Sender, record: KeyRecord) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::parse(&format!(
            r#"
            domain = "receiver.example"
            authority = "{AUTHORITY}"
            listen = "127.0.0.1:0"
            data_dir = "{}"
            [[mailbox]]
            address = "bob@receiver.example"
            [[mailbox]]
            address = "carol@receiver.example"
            "#,
            dir.path().display()
        ))
        .unwrap();
        let idempotency =
            IdempotencyStore::open(&config.idempotency_log(), SystemTime::now()).unwrap();
        let router = router(App {
            config,
            keys: Box::new(FixedKey {
                keyid: sender.keyid.clone(),
                record,
            }),
            idempotency,
        });
        Self { dir, router }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn delivered(&self, maildir: &str) -> Vec<PathBuf> {
        let new = self.dir.path().join("mail").join(maildir).join("new");
        std::fs::read_dir(new)
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default()
    }
}

fn problem_type(identifier: &str) -> Value {
    json!(format!("https://idmx-project.org/problems/{identifier}"))
}

#[tokio::test]
async fn deliver_should_accept_known_recipient() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);

    let response = receiver
        .send(Delivery::to(&["bob@receiver.example"]).build(&sender))
        .await;

    assert_eq!(
        response,
        (
            StatusCode::OK,
            json!({"results": [{"recipient": "bob@receiver.example", "status": "accepted"}]})
        )
    );
}

#[tokio::test]
async fn deliver_should_store_message_with_trace_headers_and_without_forged_results() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);

    receiver
        .send(Delivery::to(&["bob@receiver.example"]).build(&sender))
        .await;

    let stored = std::fs::read_to_string(&receiver.delivered("bob")[0]).unwrap();
    let (trace, original) = stored.split_once("From: Alice").unwrap();
    assert!(
        trace.starts_with(
            "Received: from sender.example by idmx.receiver.example with IDMX\r\n    id key-1\r\n    for <bob@receiver.example>; "
        ) && trace.ends_with(
            "Authentication-Results: idmx.receiver.example;\r\n    idmx=pass header.d=sender.example header.s=s1\r\n"
        ) && original == " <alice@sender.example>\r\nSubject: Hello\r\n\r\nHello Bob\r\n",
        "unexpected stored message:\n{stored}"
    );
}

#[tokio::test]
async fn deliver_should_report_each_recipient_in_envelope_order() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let delivery = Delivery::to(&["nobody@receiver.example", "carol@receiver.example"]);

    let (_, body) = receiver.send(delivery.build(&sender)).await;

    assert_eq!(
        body,
        json!({"results": [
            {"recipient": "nobody@receiver.example", "status": "rejected",
             "problem": {"type": problem_type("recipient_not_found")}},
            {"recipient": "carol@receiver.example", "status": "accepted"},
        ]})
    );
}

#[tokio::test]
async fn deliver_should_replay_response_without_delivering_twice() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let delivery = Delivery::to(&["bob@receiver.example"]);
    let first = receiver.send(delivery.build(&sender)).await;

    let second = receiver.send(delivery.build(&sender)).await;

    assert_eq!((second, receiver.delivered("bob").len()), (first, 1));
}

#[tokio::test]
async fn deliver_should_report_conflict_when_key_reused_for_other_content() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    receiver
        .send(Delivery::to(&["bob@receiver.example"]).build(&sender))
        .await;
    let mut other = Delivery::to(&["bob@receiver.example"]);
    other.message = b"Subject: other\r\n\r\n".to_vec();

    let (status, body) = receiver.send(other.build(&sender)).await;

    assert_eq!(
        (status, &body["type"]),
        (StatusCode::CONFLICT, &problem_type("idempotency_conflict"))
    );
}

#[tokio::test]
async fn deliver_should_reject_body_modified_after_signing() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let (parts, _) = Delivery::to(&["bob@receiver.example"])
        .build(&sender)
        .into_parts();
    let length: usize = parts.headers["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let tampered = Request::from_parts(parts, Body::from(vec![b'x'; length]));

    let (status, body) = receiver.send(tampered).await;

    assert_eq!(
        (status, &body["type"]),
        (StatusCode::UNAUTHORIZED, &problem_type("invalid_signature"))
    );
}

#[tokio::test]
async fn deliver_should_reject_signature_older_than_clock_skew() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let mut delivery = Delivery::to(&["bob@receiver.example"]);
    delivery.created = SystemTime::now() - Duration::from_mins(6);

    let (status, _) = receiver.send(delivery.build(&sender)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deliver_should_reject_revoked_key() {
    let sender = Sender::new();
    let receiver = Receiver::with_key_record(&sender, KeyRecord::Revoked);

    let (status, _) = receiver
        .send(Delivery::to(&["bob@receiver.example"]).build(&sender))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deliver_should_reject_request_signed_for_other_authority() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let mut delivery = Delivery::to(&["bob@receiver.example"]);
    delivery.authority = "idmx.other.example";

    let (status, body) = receiver.send(delivery.build(&sender)).await;

    assert_eq!(
        (status, &body["type"]),
        (StatusCode::UNAUTHORIZED, &problem_type("invalid_signature"))
    );
}

#[tokio::test]
async fn deliver_should_reject_sender_outside_signing_domain() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let mut delivery = Delivery::to(&["bob@receiver.example"]);
    delivery.from = "mallory@victim.example";

    let (status, _) = receiver.send(delivery.build(&sender)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deliver_should_reject_recipients_of_foreign_domain() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);

    let (status, body) = receiver
        .send(Delivery::to(&["bob@elsewhere.example"]).build(&sender))
        .await;

    assert_eq!(
        (status, &body["type"]),
        (StatusCode::FORBIDDEN, &problem_type("policy_rejected"))
    );
}

#[tokio::test]
async fn deliver_should_reject_request_without_signature_headers() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let mut request = Delivery::to(&["bob@receiver.example"]).build(&sender);
    request.headers_mut().remove("signature");

    let (status, body) = receiver.send(request).await;

    // `spec/signing.md` §1: an unsigned request is `invalid_signature`.
    assert_eq!(
        (status, &body["type"]),
        (StatusCode::UNAUTHORIZED, &problem_type("invalid_signature"))
    );
}

#[tokio::test]
async fn deliver_should_reject_declared_length_above_max_message_size() {
    let sender = Sender::new();
    let receiver = Receiver::new(&sender);
    let mut request = Delivery::to(&["bob@receiver.example"]).build(&sender);
    request
        .headers_mut()
        .insert("content-length", "26214401".parse().unwrap());

    let (status, body) = receiver.send(request).await;

    assert_eq!(
        (status, &body["type"]),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            &problem_type("message_too_large")
        )
    );
}

#[tokio::test]
async fn capabilities_should_advertise_versions_and_limits() {
    let receiver = Receiver::new(&Sender::new());
    let request = Request::get("/v1/capabilities")
        .body(Body::empty())
        .unwrap();

    let (_, body) = receiver.send(request).await;

    assert_eq!(
        (
            &body["versions"],
            &body["max_message_size"],
            &body["max_recipients"]
        ),
        (&json!(["v1"]), &json!(26_214_400), &json!(100))
    );
}

#[tokio::test]
async fn unknown_major_version_should_be_unsupported_version() {
    let receiver = Receiver::new(&Sender::new());
    let request = Request::get("/v2/capabilities")
        .body(Body::empty())
        .unwrap();

    let (status, body) = receiver.send(request).await;

    assert_eq!(
        (status, &body["type"]),
        (StatusCode::NOT_FOUND, &problem_type("unsupported_version"))
    );
}
