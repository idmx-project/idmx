//! Checks the delivery types against `spec/test-vectors/delivery-*.json`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use idmx_core::body::decode;
use idmx_core::envelope::Envelope;
use idmx_core::problem::{Problem, ProblemKind};
use idmx_core::result::{DeliveryResult, Outcome};
use serde_json::Value;

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors")
}

fn load_json(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(vector_dir().join(name)).unwrap()).unwrap()
}

fn load_file(vector: &Value, field: &str) -> Vec<u8> {
    std::fs::read(vector_dir().join(vector[field].as_str().unwrap())).unwrap()
}

#[test]
fn decode_yields_vector_envelope() {
    let vector = load_json("delivery-basic.json");
    let body = load_file(&vector, "body_file");
    let expected: Envelope = serde_json::from_value(vector["envelope"].clone()).unwrap();

    let decoded = decode(vector["content_type"].as_str().unwrap(), &body).unwrap();

    assert_eq!(decoded.envelope, expected);
}

#[test]
fn decode_yields_vector_message_bytes() {
    let vector = load_json("delivery-basic.json");
    let body = load_file(&vector, "body_file");

    let decoded = decode(vector["content_type"].as_str().unwrap(), &body).unwrap();

    assert_eq!(decoded.message, load_file(&vector, "message_file"));
}

#[test]
fn delivery_result_vector_parses_to_one_outcome_per_status() {
    let vector = load_json("delivery-result.json");

    let result: DeliveryResult = serde_json::from_value(vector).unwrap();

    let outcomes: Vec<_> = result.results.into_iter().map(|r| r.outcome).collect();
    assert_eq!(
        outcomes,
        [
            Outcome::Accepted,
            Outcome::Rejected {
                problem: Problem::new(ProblemKind::RecipientNotFound)
            },
            Outcome::Deferred {
                problem: Problem::new(ProblemKind::MailboxFull),
                retry_after: Some(Duration::from_hours(1)),
            },
        ]
    );
}
