//! The capabilities document (`GET /v1/capabilities`, `spec/capabilities.md`).

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The major version this crate implements, as a URL path segment.
pub const VERSION: &str = "v1";

/// Senders treat a larger `discovery_pin_max_age` as this (`spec/discovery.md`
/// §3.1): one year of 365.25 days, 31 557 600 seconds.
pub const MAX_PIN_AGE: Duration = Duration::from_hours(8766);

/// Limits and versions a receiver advertises. Unknown members are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// All major versions the receiver serves. Absent means `["v1"]`.
    #[serde(default = "default_versions")]
    pub versions: Vec<String>,
    /// Largest accepted request body in bytes.
    pub max_message_size: u64,
    /// Largest accepted number of recipients. Absent means 100.
    #[serde(default = "default_max_recipients")]
    pub max_recipients: u64,
    /// Seconds a sender may pin this domain's IDMX support. Absent means 0.
    #[serde(default)]
    pub discovery_pin_max_age: u64,
    /// Where to report abuse: a `mailto:` URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_contact: Option<String>,
}

fn default_versions() -> Vec<String> {
    vec![VERSION.to_owned()]
}

fn default_max_recipients() -> u64 {
    100
}

impl Capabilities {
    /// Whether the receiver serves the major version this crate implements.
    #[must_use]
    pub fn supports_this_version(&self) -> bool {
        self.versions.iter().any(|version| version == VERSION)
    }

    /// How long a positive discovery result may be pinned, at most
    /// [`MAX_PIN_AGE`]; `None` = no pin.
    #[must_use]
    pub fn pin_max_age(&self) -> Option<Duration> {
        (self.discovery_pin_max_age > 0)
            .then(|| Duration::from_secs(self.discovery_pin_max_age).min(MAX_PIN_AGE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Capabilities {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn deserialize_should_default_versions_to_v1() {
        assert!(parse(r#"{"max_message_size":26214400}"#).supports_this_version());
    }

    #[test]
    fn deserialize_should_default_max_recipients_to_100() {
        assert_eq!(
            parse(r#"{"max_message_size":26214400}"#).max_recipients,
            100
        );
    }

    #[test]
    fn deserialize_should_ignore_unknown_members() {
        let capabilities = parse(r#"{"max_message_size":1,"new":{"x":true}}"#);

        assert_eq!(capabilities.max_message_size, 1);
    }

    #[test]
    fn supports_this_version_should_be_false_when_only_newer_majors_listed() {
        let capabilities = parse(r#"{"versions":["v2","v3"],"max_message_size":1}"#);

        assert!(!capabilities.supports_this_version());
    }

    #[test]
    fn pin_max_age_should_be_clamped_to_one_year() {
        let capabilities = parse(r#"{"max_message_size":1,"discovery_pin_max_age":99999999999}"#);

        assert_eq!(capabilities.pin_max_age(), Some(MAX_PIN_AGE));
    }

    #[test]
    fn pin_max_age_should_be_none_for_zero() {
        assert_eq!(parse(r#"{"max_message_size":1}"#).pin_max_age(), None);
    }
}
