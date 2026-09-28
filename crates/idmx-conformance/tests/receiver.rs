//! The suite against a real `idmxd` router (must conform) and against a
//! deliberately broken receiver (must be caught), over plain HTTP/2.

use std::net::SocketAddr;
use std::time::SystemTime;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::get;
use ed25519_dalek::SigningKey;
use idmx_conformance::delivery::DeliveryProbe;
use idmx_conformance::report::{Outcome, Report};
use idmx_conformance::{Origin, http_client_builder, run};
use idmx_core::discovery::KeyLookupError;
use idmx_core::key::{KeyId, KeyRecord};
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

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn keyid() -> KeyId {
    "s1._idmxkey.sender.example".parse().unwrap()
}

fn probe() -> DeliveryProbe {
    DeliveryProbe::new(
        signing_key(),
        keyid(),
        "bob@receiver.example".parse().unwrap(),
    )
}

async fn run_against(app: Router, listener: tokio::net::TcpListener) -> Report {
    let address: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let http = http_client_builder()
        .http2_prior_knowledge()
        .resolve("localhost", address)
        .build()
        .unwrap();
    let origin: Origin = format!("http://localhost:{}", address.port())
        .parse()
        .unwrap();
    run(&http, &origin, Some(&probe())).await
}

async fn idmxd_report() -> Report {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Config::parse(&format!(
        r#"
        domain = "receiver.example"
        authority = "localhost:{}"
        listen = "{address}"
        data_dir = "{}"
        discovery_pin_max_age = 604800
        abuse_contact = "mailto:abuse@receiver.example"
        [[mailbox]]
        address = "bob@receiver.example"
        "#,
        address.port(),
        dir.path().display()
    ))
    .unwrap();
    let idempotency = IdempotencyStore::open(&config.idempotency_log(), SystemTime::now()).unwrap();
    let app = router(App {
        config,
        keys: Box::new(FixedKey {
            keyid: keyid(),
            record: KeyRecord::Active(signing_key().verifying_key()),
        }),
        idempotency,
    });
    run_against(app, listener).await
}

/// Answers `200` to everything and advertises a document below the floors.
async fn broken_report() -> Report {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = Router::new()
        .route(
            "/v1/capabilities",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"max_message_size":1000,"versions":["v2"]}"#,
                )
            }),
        )
        .fallback(|| async { StatusCode::OK });
    run_against(app, listener).await
}

fn ids_with(report: &Report, wanted: fn(&Outcome) -> bool) -> Vec<&'static str> {
    report
        .checks
        .iter()
        .filter(|check| wanted(&check.outcome))
        .map(|check| check.id)
        .collect()
}

fn failed(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Fail(_))
}

fn not_passed(outcome: &Outcome) -> bool {
    *outcome != Outcome::Pass
}

#[tokio::test]
async fn run_should_pass_every_check_against_idmxd() {
    let report = idmxd_report().await;

    assert_eq!(
        ids_with(&report, not_passed),
        Vec::<&str>::new(),
        "{report}"
    );
}

#[tokio::test]
async fn run_should_report_each_violation_of_a_broken_receiver() {
    let report = broken_report().await;

    assert_eq!(
        ids_with(&report, failed),
        [
            "CAP-02", "CAP-04", "CAP-06", "CAP-08", "VER-01", "SIG-01", "SIG-02", "SIG-03",
            "SIG-04", "SIG-05", "SIG-06", "REQ-01", "REQ-02", "REQ-03", "REQ-04", "DLV-01",
            "IDM-02", "DLV-02", "DLV-03",
        ],
        "{report}"
    );
}

#[tokio::test]
async fn conforms_should_be_false_for_a_broken_receiver() {
    assert!(!broken_report().await.conforms());
}
