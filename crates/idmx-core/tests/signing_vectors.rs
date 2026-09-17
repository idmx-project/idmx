//! Checks `idmx-core` against the implementation-independent vectors in
//! `spec/test-vectors/`.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use idmx_core::key::{KeyId, KeyRecord};
use idmx_core::signing::{
    MAX_CLOCK_SKEW, Request, SignatureHeaders, UnverifiedSignature, VerifyError, sign,
};
use serde_json::Value;

struct Vector {
    json: Value,
    body: Vec<u8>,
}

impl Vector {
    fn load() -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
        let json: Value =
            serde_json::from_slice(&std::fs::read(dir.join("signing-basic.json")).unwrap())
                .unwrap();
        let body = std::fs::read(dir.join(json["request"]["body_file"].as_str().unwrap())).unwrap();
        Self { json, body }
    }

    fn str(&self, pointer: &str) -> &str {
        self.json.pointer(pointer).and_then(Value::as_str).unwrap()
    }

    fn request(&self) -> Request<'_> {
        Request {
            method: self.str("/request/method"),
            authority: self.str("/request/authority"),
            path: self.str("/request/path"),
            content_type: self.str("/request/content_type"),
            idempotency_key: self.str("/request/idempotency_key"),
            body: &self.body,
        }
    }

    fn created(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.json["created"].as_u64().unwrap())
    }

    fn signing_key(&self) -> SigningKey {
        let seed: [u8; 32] = hex::decode(self.str("/private_key_seed_hex"))
            .unwrap()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn expected_headers(&self) -> SignatureHeaders {
        SignatureHeaders {
            content_digest: self.str("/expected/content_digest").to_owned(),
            signature_input: self.str("/expected/signature_input").to_owned(),
            signature: self.str("/expected/signature").to_owned(),
        }
    }
}

#[test]
fn sign_reproduces_expected_headers() {
    let vector = Vector::load();
    let keyid: KeyId = vector.str("/keyid").parse().unwrap();

    let headers = sign(
        &vector.request(),
        &vector.signing_key(),
        &keyid,
        vector.created(),
    )
    .unwrap();

    assert_eq!(headers, vector.expected_headers());
}

#[test]
fn parse_builds_expected_signature_base() {
    let vector = Vector::load();

    let unverified = UnverifiedSignature::parse(
        &vector.request(),
        &vector.expected_headers(),
        vector.created(),
    )
    .unwrap();

    assert_eq!(
        unverified.signature_base(),
        vector.str("/expected/signature_base")
    );
}

#[test]
fn expected_signature_verifies_with_published_key_record() {
    let vector = Vector::load();
    let KeyRecord::Active(key) = vector.str("/key_record_txt").parse().unwrap() else {
        panic!("vector key record must be active");
    };
    let unverified = UnverifiedSignature::parse(
        &vector.request(),
        &vector.expected_headers(),
        vector.created(),
    )
    .unwrap();

    let result = unverified.verify(&key);

    assert_eq!(result, Ok(()));
}

#[test]
fn parse_rejects_created_outside_clock_skew() {
    let vector = Vector::load();
    let now = vector.created() + MAX_CLOCK_SKEW + Duration::from_secs(1);

    let result = UnverifiedSignature::parse(&vector.request(), &vector.expected_headers(), now);

    assert_eq!(result.unwrap_err(), VerifyError::CreatedOutOfWindow);
}

#[test]
fn parse_accepts_created_ahead_of_receiver_clock_within_skew() {
    let vector = Vector::load();
    let now = vector.created() - MAX_CLOCK_SKEW;

    let result = UnverifiedSignature::parse(&vector.request(), &vector.expected_headers(), now);

    assert!(result.is_ok(), "unexpected: {result:?}");
}

#[test]
fn parse_rejects_modified_body() {
    let vector = Vector::load();
    let mut body = vector.body.clone();
    body[0] ^= 1;
    let request = Request {
        body: &body,
        ..vector.request()
    };

    let result = UnverifiedSignature::parse(&request, &vector.expected_headers(), vector.created());

    assert_eq!(result.unwrap_err(), VerifyError::DigestMismatch);
}

#[test]
fn verify_rejects_request_replayed_to_other_authority() {
    let vector = Vector::load();
    let request = Request {
        authority: "idmx.attacker.example",
        ..vector.request()
    };
    let unverified =
        UnverifiedSignature::parse(&request, &vector.expected_headers(), vector.created()).unwrap();

    let result = unverified.verify(&vector.signing_key().verifying_key());

    assert_eq!(result, Err(VerifyError::BadSignature));
}

#[test]
fn verify_rejects_swapped_idempotency_key() {
    let vector = Vector::load();
    let request = Request {
        idempotency_key: "01J8ZQ4M9X6T3V5B7N2K0HXXXX",
        ..vector.request()
    };
    let unverified =
        UnverifiedSignature::parse(&request, &vector.expected_headers(), vector.created()).unwrap();

    let result = unverified.verify(&vector.signing_key().verifying_key());

    assert_eq!(result, Err(VerifyError::BadSignature));
}

#[test]
fn parse_rejects_missing_covered_component() {
    let vector = Vector::load();
    let headers = SignatureHeaders {
        signature_input: vector
            .str("/expected/signature_input")
            .replace(" \"idempotency-key\"", ""),
        ..vector.expected_headers()
    };

    let result = UnverifiedSignature::parse(&vector.request(), &headers, vector.created());

    assert_eq!(result.unwrap_err(), VerifyError::CoveredComponents);
}

#[test]
fn parse_rejects_other_algorithm() {
    let vector = Vector::load();
    let headers = SignatureHeaders {
        signature_input: vector
            .str("/expected/signature_input")
            .replace("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\""),
        ..vector.expected_headers()
    };

    let result = UnverifiedSignature::parse(&vector.request(), &headers, vector.created());

    assert_eq!(result.unwrap_err(), VerifyError::UnsupportedAlgorithm);
}

#[test]
fn parse_ignores_signatures_with_other_tags() {
    let vector = Vector::load();
    let headers = SignatureHeaders {
        signature_input: format!(
            "proxy=(\"@method\");created=1;tag=\"other\", {}",
            vector.str("/expected/signature_input")
        ),
        ..vector.expected_headers()
    };

    let result = UnverifiedSignature::parse(&vector.request(), &headers, vector.created());

    assert!(result.is_ok(), "unexpected: {result:?}");
}

#[test]
fn parse_rejects_headers_without_idmx_tag() {
    let vector = Vector::load();
    let headers = SignatureHeaders {
        signature_input: vector
            .str("/expected/signature_input")
            .replace("idmx-v1", "idmx-v2"),
        ..vector.expected_headers()
    };

    let result = UnverifiedSignature::parse(&vector.request(), &headers, vector.created());

    assert_eq!(result.unwrap_err(), VerifyError::NoSignature);
}
