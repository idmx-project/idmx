//! Replays `spec/test-vectors/mailbox.json` through the mailbox parser.

use std::path::Path;

use idmx_core::mailbox::{Mailbox, MailboxError};
use serde_json::Value;

#[test]
fn mailbox_vectors_yield_expected_outcome() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors/mailbox.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();

    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let result = case["address"].as_str().unwrap().parse::<Mailbox>();

        let outcome = match result {
            Ok(_) => "valid",
            Err(MailboxError::NotMinimal) => "not_minimal",
            Err(_) => "invalid",
        };
        assert_eq!(outcome, case["expected"].as_str().unwrap(), "{name}");
    }
}
