//! Checks on the capabilities document (`spec/capabilities.md` §3, §4).
//!
//! The document is inspected as raw JSON on purpose: a typed parser would
//! apply defaults and hide exactly the deviations these checks look for.

use serde_json::{Map, Value};

use crate::report::{Check, Level, Outcome};

const MIN_MAX_MESSAGE_SIZE: u64 = 26_214_400;
const MIN_MAX_RECIPIENTS: u64 = 100;
const RECOMMENDED_PIN_MAX_AGE: u64 = 604_800;

/// Checks every member of §3 against its allowed range.
pub(crate) fn check_document(document: &Map<String, Value>) -> Vec<Check> {
    vec![
        Check {
            id: "CAP-02",
            spec: "capabilities.md §3",
            level: Level::Must,
            requirement: "max_message_size is an integer of at least 25 MiB",
            outcome: at_least(
                document.get("max_message_size"),
                MIN_MAX_MESSAGE_SIZE,
                false,
            ),
        },
        Check {
            id: "CAP-03",
            spec: "capabilities.md §3",
            level: Level::Must,
            requirement: "max_recipients is absent or an integer of at least 100",
            outcome: at_least(document.get("max_recipients"), MIN_MAX_RECIPIENTS, true),
        },
        Check {
            id: "CAP-04",
            spec: "discovery.md §5",
            level: Level::Must,
            requirement: "versions is absent or a list of major versions that includes v1",
            outcome: versions(document.get("versions")),
        },
        Check {
            id: "CAP-05",
            spec: "capabilities.md §3",
            level: Level::Must,
            requirement: "discovery_pin_max_age is absent or a non-negative integer",
            outcome: at_least(document.get("discovery_pin_max_age"), 0, true),
        },
        Check {
            id: "CAP-06",
            spec: "discovery.md §3.1",
            level: Level::Should,
            requirement: "discovery_pin_max_age is 604800 (7 days)",
            outcome: recommended_pin(document.get("discovery_pin_max_age")),
        },
        Check {
            id: "CAP-07",
            spec: "capabilities.md §3",
            level: Level::Must,
            requirement: "abuse_contact is absent or a mailto: URI without header fields",
            outcome: abuse_contact(document.get("abuse_contact")),
        },
    ]
}

/// `Cache-Control` of the capabilities response (§4).
pub(crate) fn check_cache_control(header: Option<&str>) -> Check {
    let has_max_age = header.is_some_and(|value| {
        value.split(',').any(|directive| {
            directive
                .trim()
                .to_ascii_lowercase()
                .starts_with("max-age=")
        })
    });
    Check {
        id: "CAP-08",
        spec: "capabilities.md §4",
        level: Level::Should,
        requirement: "the response carries Cache-Control with max-age",
        outcome: if has_max_age {
            Outcome::Pass
        } else {
            Outcome::Fail(format!("Cache-Control: {}", header.unwrap_or("<absent>")))
        },
    }
}

fn at_least(value: Option<&Value>, floor: u64, optional: bool) -> Outcome {
    match value {
        None if optional => Outcome::Pass,
        None => Outcome::Fail("member is missing".to_owned()),
        Some(value) => match value.as_u64() {
            Some(number) if number >= floor => Outcome::Pass,
            Some(number) => Outcome::Fail(format!("{number} is below {floor}")),
            None => Outcome::Fail(format!("{value} is not a non-negative integer")),
        },
    }
}

fn versions(value: Option<&Value>) -> Outcome {
    let Some(value) = value else {
        return Outcome::Pass;
    };
    let Some(list) = value.as_array() else {
        return Outcome::Fail(format!("{value} is not an array"));
    };
    if let Some(bad) = list.iter().find(|entry| !is_major_version(entry)) {
        return Outcome::Fail(format!("{bad} is not a major version like \"v1\""));
    }
    if !list.iter().any(|entry| entry == "v1") {
        return Outcome::Fail(format!("{value} is served under /v1/ but does not list v1"));
    }
    let duplicate = list
        .iter()
        .enumerate()
        .find(|(index, entry)| list[..*index].contains(entry));
    match duplicate {
        Some((_, entry)) => Outcome::Fail(format!("{entry} is listed twice")),
        None => Outcome::Pass,
    }
}

fn is_major_version(entry: &Value) -> bool {
    entry
        .as_str()
        .and_then(|text| text.strip_prefix('v'))
        .is_some_and(|digits| {
            !digits.is_empty()
                && !digits.starts_with('0')
                && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn recommended_pin(value: Option<&Value>) -> Outcome {
    match value.and_then(Value::as_u64) {
        Some(RECOMMENDED_PIN_MAX_AGE) => Outcome::Pass,
        Some(other) => Outcome::Fail(format!("advertises {other}")),
        None => Outcome::Fail("advertises no pin".to_owned()),
    }
}

fn abuse_contact(value: Option<&Value>) -> Outcome {
    let Some(value) = value else {
        return Outcome::Pass;
    };
    let is_mailto = value
        .as_str()
        .and_then(|text| text.strip_prefix("mailto:"))
        .is_some_and(|address| address.contains('@') && !address.contains('?'));
    if is_mailto {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("{value} is not a plain mailto: URI"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome_of(id: &str, json: &str) -> Outcome {
        let document: Map<String, Value> = serde_json::from_str(json).unwrap();
        check_document(&document)
            .into_iter()
            .find(|check| check.id == id)
            .unwrap()
            .outcome
    }

    #[test]
    fn check_document_should_pass_minimal_document() {
        let document: Map<String, Value> =
            serde_json::from_str(r#"{"max_message_size":26214400}"#).unwrap();

        let violations = check_document(&document)
            .iter()
            .filter(|check| check.is_violation())
            .count();

        assert_eq!(violations, 0);
    }

    #[test]
    fn check_document_should_fail_when_max_message_size_missing() {
        assert!(matches!(outcome_of("CAP-02", "{}"), Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_max_message_size_below_floor() {
        let outcome = outcome_of("CAP-02", r#"{"max_message_size":1000}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_max_recipients_below_floor() {
        let outcome = outcome_of("CAP-03", r#"{"max_recipients":10}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_versions_lacks_v1() {
        let outcome = outcome_of("CAP-04", r#"{"versions":["v2"]}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_version_has_leading_zero() {
        let outcome = outcome_of("CAP-04", r#"{"versions":["v1","v02"]}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_version_listed_twice() {
        let outcome = outcome_of("CAP-04", r#"{"versions":["v1","v1"]}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_pin_max_age_negative() {
        let outcome = outcome_of("CAP-05", r#"{"discovery_pin_max_age":-1}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_fail_when_abuse_contact_is_https() {
        let outcome = outcome_of("CAP-07", r#"{"abuse_contact":"https://example.org/abuse"}"#);

        assert!(matches!(outcome, Outcome::Fail(_)));
    }

    #[test]
    fn check_document_should_pass_mailto_abuse_contact() {
        let outcome = outcome_of("CAP-07", r#"{"abuse_contact":"mailto:abuse@example.org"}"#);

        assert_eq!(outcome, Outcome::Pass);
    }

    #[test]
    fn check_cache_control_should_pass_with_max_age() {
        let check = check_cache_control(Some("public, max-age=3600"));

        assert_eq!(check.outcome, Outcome::Pass);
    }

    #[test]
    fn check_cache_control_should_fail_when_absent() {
        assert!(matches!(
            check_cache_control(None).outcome,
            Outcome::Fail(_)
        ));
    }
}
