//! Replays `spec/test-vectors/signing-negative.json` through the verification
//! procedure of `spec/signing.md` §7.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use idmx_core::body::decode;
use idmx_core::idempotency::IdempotencyKey;
use idmx_core::key::KeyRecord;
use idmx_core::signing::{Request, SignatureHeaders, UnverifiedSignature, VerifyError};
use serde_json::Value;

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors")
}

fn load_json(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(vector_dir().join(name)).unwrap()).unwrap()
}

/// The case's value at `pointer` if it names one, else the base vector's at
/// `base_pointer`.
fn pick<'a>(case: &'a Value, pointer: &str, base: &'a Value, base_pointer: &str) -> &'a Value {
    case.pointer(pointer)
        .unwrap_or_else(|| base.pointer(base_pointer).unwrap())
}

/// Steps 1–6 of `signing.md` §7; every failure maps to `invalid_signature`.
fn verify(case: &Value, base: &Value, body: &[u8]) -> Result<(), VerifyError> {
    let text = |pointer: &str, base_pointer: &str| {
        pick(case, pointer, base, base_pointer).as_str().unwrap()
    };
    let idempotency_key: IdempotencyKey =
        text("/request/idempotency_key", "/request/idempotency_key")
            .parse()
            .unwrap();
    let content_type = text("/request/content_type", "/request/content_type");
    let request = Request {
        method: text("/request/method", "/request/method"),
        authority: text("/request/authority", "/request/authority"),
        path: text("/request/path", "/request/path"),
        content_type,
        idempotency_key: &idempotency_key,
        body,
    };
    let headers = SignatureHeaders {
        content_digest: text("/headers/content_digest", "/expected/content_digest").to_owned(),
        signature_input: text("/headers/signature_input", "/expected/signature_input").to_owned(),
        signature: text("/headers/signature", "/expected/signature").to_owned(),
    };
    let now: SystemTime =
        UNIX_EPOCH + Duration::from_secs(pick(case, "/now", base, "/created").as_u64().unwrap());
    let record: KeyRecord = text("/key_record_txt", "/key_record_txt").parse().unwrap();

    let verified = UnverifiedSignature::parse(&request, &headers, now)?.verify(&record)?;
    let envelope = decode(content_type, body).unwrap().envelope;
    verified.check_sender(envelope.from())
}

#[test]
fn every_case_yields_its_expected_outcome() {
    let vectors = load_json("signing-negative.json");
    let base = load_json(vectors["base"].as_str().unwrap());
    let body =
        std::fs::read(vector_dir().join(base["request"]["body_file"].as_str().unwrap())).unwrap();

    let outcomes: Vec<(&str, &str)> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let outcome = match verify(case, &base, &body) {
                Ok(()) => "valid",
                Err(_) => "invalid_signature",
            };
            (case["name"].as_str().unwrap(), outcome)
        })
        .collect();
    let expected: Vec<(&str, &str)> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["name"].as_str().unwrap(),
                case["expected"].as_str().unwrap(),
            )
        })
        .collect();

    assert_eq!(outcomes, expected);
}

#[test]
fn foreign_sender_domain_fails_only_at_the_sender_check() {
    let vectors = load_json("signing-negative.json");
    let base = load_json(vectors["base"].as_str().unwrap());
    let body =
        std::fs::read(vector_dir().join(base["request"]["body_file"].as_str().unwrap())).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "foreign-sender-domain")
        .unwrap();

    let result = verify(case, &base, &body);

    assert!(
        matches!(result, Err(VerifyError::SenderDomainMismatch { .. })),
        "unexpected: {result:?}"
    );
}
