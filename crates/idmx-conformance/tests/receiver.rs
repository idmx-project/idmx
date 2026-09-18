//! The suite against a real `idmxd` router (must conform) and against a
//! deliberately broken receiver (must be caught), over plain HTTP/2.

use std::net::SocketAddr;
use std::time::SystemTime;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::get;
use idmx_conformance::report::{Outcome, Report};
use idmx_conformance::{Origin, http_client_builder, run};
use idmx_server::app::{App, router};
use idmx_server::config::Config;
use idmx_server::idempotency::IdempotencyStore;
use idmx_server::keys::{KeyFuture, KeySource};

struct NoKeys;

impl KeySource for NoKeys {
    fn fetch<'a>(&'a self, keyid: &'a idmx_core::key::KeyId) -> KeyFuture<'a> {
        Box::pin(async move {
            Err(idmx_core::discovery::KeyLookupError::NotFound(
                keyid.clone(),
            ))
        })
    }
}

async fn run_against(app: Router, listener: tokio::net::TcpListener) -> Report {
    let address: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let http = http_client_builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let origin: Origin = format!("http://{address}").parse().unwrap();
    run(&http, &origin).await
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
        "#,
        address.port(),
        dir.path().display()
    ))
    .unwrap();
    let idempotency = IdempotencyStore::open(&config.idempotency_log(), SystemTime::now()).unwrap();
    let app = router(App {
        config,
        keys: Box::new(NoKeys),
        idempotency,
    });
    run_against(app, listener).await
}

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

fn failed_ids(report: &Report) -> Vec<&'static str> {
    report
        .checks
        .iter()
        .filter(|check| matches!(check.outcome, Outcome::Fail(_)))
        .map(|check| check.id)
        .collect()
}

#[tokio::test]
async fn run_should_pass_every_check_against_idmxd() {
    let report = idmxd_report().await;

    assert_eq!(failed_ids(&report), Vec::<&str>::new(), "{report}");
}

#[tokio::test]
async fn run_should_report_each_violation_of_a_broken_receiver() {
    let report = broken_report().await;

    assert_eq!(
        failed_ids(&report),
        ["CAP-02", "CAP-04", "CAP-06", "CAP-08", "VER-01", "SIG-01"],
        "{report}"
    );
}

#[tokio::test]
async fn conforms_should_be_false_for_a_broken_receiver() {
    assert!(!broken_report().await.conforms());
}
