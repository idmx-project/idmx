//! Sender against a real `idmxd` router over plain HTTP/2 on localhost.
//! Discovery and TLS are out of scope here (no DNS zone in unit tests); the
//! devnet covers them.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use hickory_resolver::TokioResolver;
use idmx_client::identity::Identity;
use idmx_client::sender::{Attempt, SendError, Sender, http_client_builder};
use idmx_core::discovery::KeyLookupError;
use idmx_core::envelope::{Envelope, ReversePath};
use idmx_core::key::{KeyId, KeyRecord};
use idmx_core::problem::{ProblemKind, ProblemType};
use idmx_core::result::Outcome;
use idmx_server::app::{App, router};
use idmx_server::config::Config;
use idmx_server::idempotency::IdempotencyStore;
use idmx_server::keys::{KeyFuture, KeySource};

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

/// A running receiver plus a sender wired to it.
struct Devnet {
    dir: tempfile::TempDir,
    origin: String,
    authority: String,
    sender: Sender,
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn keyid() -> KeyId {
    "s1._idmxkey.sender.example".parse().unwrap()
}

impl Devnet {
    /// `published` is the key the receiver finds "in DNS" for the sender.
    async fn start(published: KeyRecord) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let authority = format!("localhost:{}", address.port());

        let config = Config::parse(&format!(
            r#"
            domain = "receiver.example"
            authority = "{authority}"
            listen = "{address}"
            data_dir = "{}"
            [[mailbox]]
            address = "bob@receiver.example"
            "#,
            dir.path().display()
        ))
        .unwrap();
        let idempotency =
            IdempotencyStore::open(&config.idempotency_log(), SystemTime::now()).unwrap();
        let app = router(App {
            config,
            keys: Box::new(FixedKey {
                keyid: keyid(),
                record: published,
            }),
            idempotency,
        });
        tokio::spawn(async move { axum::serve(listener, app).await });

        let http = http_client_builder()
            .http2_prior_knowledge()
            .resolve("localhost", address)
            .build()
            .unwrap();
        let resolver = TokioResolver::builder_tokio().unwrap().build().unwrap();
        Self {
            dir,
            origin: format!("http://{authority}"),
            authority,
            sender: Sender::new(http, resolver, Identity::new(signing_key(), keyid())),
        }
    }

    async fn deliver(&self, from: &str, to: &[&str], key: &str) -> Result<Attempt, SendError> {
        let envelope = Envelope::new(
            ReversePath::Mailbox(from.parse().unwrap()),
            to.iter().map(|address| address.parse().unwrap()).collect(),
        )
        .unwrap();
        self.sender
            .deliver_via(
                &self.origin,
                &self.authority,
                &envelope,
                b"Subject: Hello\r\n\r\nHello Bob\r\n",
                &key.parse().unwrap(),
            )
            .await
    }

    fn delivered(&self) -> Vec<PathBuf> {
        let new = self.dir.path().join("mail/bob/new");
        std::fs::read_dir(new)
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default()
    }
}

fn active() -> KeyRecord {
    KeyRecord::Active(signing_key().verifying_key())
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_complete_with_accepted_recipient() {
    let devnet = Devnet::start(active()).await;

    let attempt = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    let Attempt::Completed(result) = attempt else {
        panic!("unexpected: {attempt:?}");
    };
    assert_eq!(result.results[0].outcome, Outcome::Accepted);
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_put_message_into_recipient_maildir() {
    let devnet = Devnet::start(active()).await;

    let _ = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    let stored = std::fs::read_to_string(&devnet.delivered()[0]).unwrap();
    assert!(
        stored.starts_with("Received: from sender.example by localhost with IDMX")
            && stored.ends_with("Subject: Hello\r\n\r\nHello Bob\r\n"),
        "unexpected stored message:\n{stored}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_not_duplicate_on_retry_with_same_key() {
    let devnet = Devnet::start(active()).await;
    let _ = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    let retry = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    assert!(
        matches!(retry, Attempt::Completed(_)) && devnet.delivered().len() == 1,
        "unexpected: {retry:?}, {} files",
        devnet.delivered().len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_report_unknown_recipient_as_rejected_result() {
    let devnet = Devnet::start(active()).await;

    let attempt = devnet
        .deliver(
            "alice@sender.example",
            &["nobody@receiver.example"],
            "key-1",
        )
        .await
        .unwrap();

    let Attempt::Completed(result) = attempt else {
        panic!("unexpected: {attempt:?}");
    };
    assert!(
        matches!(&result.results[0].outcome, Outcome::Rejected { problem }
            if problem.problem_type == ProblemType::Known(ProblemKind::RecipientNotFound)),
        "unexpected: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_classify_revoked_key_as_permanent_rejection() {
    let devnet = Devnet::start(KeyRecord::Revoked).await;

    let attempt = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    assert!(
        matches!(&attempt, Attempt::Rejected(problem)
            if problem.problem_type == ProblemType::Known(ProblemKind::InvalidSignature)),
        "unexpected: {attempt:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_classify_foreign_recipient_domain_as_policy_rejected() {
    let devnet = Devnet::start(active()).await;

    let attempt = devnet
        .deliver("alice@sender.example", &["bob@elsewhere.example"], "key-1")
        .await
        .unwrap();

    assert!(
        matches!(&attempt, Attempt::Rejected(problem)
            if problem.problem_type == ProblemType::Known(ProblemKind::PolicyRejected)),
        "unexpected: {attempt:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_fail_locally_when_sender_outside_signing_domain() {
    let devnet = Devnet::start(active()).await;

    let result = devnet
        .deliver("mallory@victim.example", &["bob@receiver.example"], "key-1")
        .await;

    assert!(
        matches!(result, Err(SendError::SenderDomain(_))),
        "unexpected: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_via_should_report_unreachable_endpoint() {
    let mut devnet = Devnet::start(active()).await;
    devnet.origin = "http://localhost:1".to_owned();

    let attempt = devnet
        .deliver("alice@sender.example", &["bob@receiver.example"], "key-1")
        .await
        .unwrap();

    assert!(
        matches!(attempt, Attempt::Unreachable(_)),
        "unexpected: {attempt:?}"
    );
}
