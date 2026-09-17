//! Key identifiers and DNS key records (`spec/signing.md` §4).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::VerifyingKey;

/// DNS label that separates the selector from the signing domain.
const KEY_LABEL: &str = "._idmxkey.";

/// Errors from parsing a [`KeyId`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyIdError {
    /// The name does not contain the `_idmxkey` label.
    #[error("keyid is not of the form <selector>._idmxkey.<domain>")]
    MissingKeyLabel,
    /// Selector or domain is empty, or the name ends with a dot.
    #[error("keyid has an empty selector or domain, or a trailing dot")]
    EmptyPart,
    /// The name contains upper-case characters.
    #[error("keyid must be lower case")]
    NotLowerCase,
}

/// The `keyid` signature parameter: the DNS name of a key record,
/// `<selector>._idmxkey.<domain>`, lower case, without trailing dot.
///
/// # Examples
///
/// ```
/// use idmx_core::key::KeyId;
///
/// let keyid: KeyId = "s1._idmxkey.sender.example".parse()?;
/// assert_eq!(keyid.selector(), "s1");
/// assert_eq!(keyid.domain(), "sender.example");
/// # Ok::<(), idmx_core::key::KeyIdError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId {
    name: String,
    selector_len: usize,
}

impl KeyId {
    /// Builds the key id for `selector` under the signing `domain`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyIdError`] if the resulting name is not a valid key id.
    pub fn new(selector: &str, domain: &str) -> Result<Self, KeyIdError> {
        format!("{selector}{KEY_LABEL}{domain}").parse()
    }

    /// The selector; one or more DNS labels.
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.name[..self.selector_len]
    }

    /// The signing domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.name[self.selector_len + KEY_LABEL.len()..]
    }

    /// The full DNS name of the key record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl FromStr for KeyId {
    type Err = KeyIdError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let Some((selector, domain)) = name.split_once(KEY_LABEL) else {
            return Err(KeyIdError::MissingKeyLabel);
        };
        if selector.is_empty() || domain.is_empty() || domain.ends_with('.') {
            return Err(KeyIdError::EmptyPart);
        }
        if name.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(KeyIdError::NotLowerCase);
        }
        Ok(Self {
            name: name.to_owned(),
            selector_len: selector.len(),
        })
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Errors from parsing a [`KeyRecord`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyRecordError {
    /// The first tag is not `v=IDMX1`.
    #[error("key record must start with v=IDMX1")]
    Version,
    /// A tag is not of the form `name=value`.
    #[error("malformed tag in key record")]
    MalformedTag,
    /// The `k` tag is missing or not `ed25519`.
    #[error("key record must have k=ed25519")]
    KeyType,
    /// The `p` tag is missing.
    #[error("key record has no p= tag")]
    MissingKey,
    /// The `p` tag is not base64 of a valid 32-byte Ed25519 public key.
    #[error("p= is not a base64-encoded Ed25519 public key")]
    InvalidKey,
}

/// A parsed `v=IDMX1` key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRecord {
    /// The record carries a usable public key.
    Active(VerifyingKey),
    /// The record has an empty `p=`: the key is revoked.
    Revoked,
}

impl KeyRecord {
    /// Renders the TXT record value for `key`.
    #[must_use]
    pub fn render(key: &VerifyingKey) -> String {
        format!("v=IDMX1; k=ed25519; p={}", BASE64.encode(key.as_bytes()))
    }
}

impl FromStr for KeyRecord {
    type Err = KeyRecordError;

    /// Parses the concatenated TXT record value. Unknown tags are ignored.
    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        let mut tags = txt
            .split(';')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(|tag| {
                tag.split_once('=')
                    .map(|(name, value)| (name.trim_end(), value.trim_start()))
                    .ok_or(KeyRecordError::MalformedTag)
            });

        if tags.next() != Some(Ok(("v", "IDMX1"))) {
            return Err(KeyRecordError::Version);
        }

        let mut key_type = None;
        let mut public_key = None;
        for tag in tags {
            match tag? {
                ("k", value) => key_type = Some(value),
                ("p", value) => public_key = Some(value),
                _ => {}
            }
        }

        if key_type != Some("ed25519") {
            return Err(KeyRecordError::KeyType);
        }
        match public_key {
            None => Err(KeyRecordError::MissingKey),
            Some("") => Ok(Self::Revoked),
            Some(encoded) => decode_public_key(encoded).map(Self::Active),
        }
    }
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, KeyRecordError> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| KeyRecordError::InvalidKey)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| KeyRecordError::InvalidKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyRecordError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod key_id {
        use super::*;

        #[test]
        fn splits_multi_label_selector_from_domain() {
            let keyid: KeyId = "a.b._idmxkey.sender.example".parse().unwrap();

            assert_eq!(
                (keyid.selector(), keyid.domain()),
                ("a.b", "sender.example")
            );
        }

        #[test]
        fn rejects_name_without_key_label() {
            let result = "s1.sender.example".parse::<KeyId>();

            assert_eq!(result, Err(KeyIdError::MissingKeyLabel));
        }

        #[test]
        fn rejects_trailing_dot() {
            let result = "s1._idmxkey.sender.example.".parse::<KeyId>();

            assert_eq!(result, Err(KeyIdError::EmptyPart));
        }

        #[test]
        fn rejects_upper_case() {
            let result = "s1._idmxkey.Sender.example".parse::<KeyId>();

            assert_eq!(result, Err(KeyIdError::NotLowerCase));
        }
    }

    mod key_record {
        use super::*;

        const RFC8463_KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

        #[test]
        fn parses_active_key() {
            let record = format!("v=IDMX1; k=ed25519; p={RFC8463_KEY}").parse::<KeyRecord>();

            assert!(
                matches!(record, Ok(KeyRecord::Active(_))),
                "unexpected: {record:?}"
            );
        }

        #[test]
        fn render_round_trips_through_parse() {
            let KeyRecord::Active(key) = format!("v=IDMX1;k=ed25519;p={RFC8463_KEY}")
                .parse()
                .unwrap()
            else {
                panic!("expected active key");
            };

            assert_eq!(KeyRecord::render(&key).parse(), Ok(KeyRecord::Active(key)));
        }

        #[test]
        fn empty_p_means_revoked() {
            let record = "v=IDMX1; k=ed25519; p=".parse::<KeyRecord>();

            assert_eq!(record, Ok(KeyRecord::Revoked));
        }

        #[test]
        fn ignores_unknown_tags() {
            let record = "v=IDMX1; x=future; k=ed25519; p=".parse::<KeyRecord>();

            assert_eq!(record, Ok(KeyRecord::Revoked));
        }

        #[test]
        fn rejects_version_not_first() {
            let record = "k=ed25519; v=IDMX1; p=".parse::<KeyRecord>();

            assert_eq!(record, Err(KeyRecordError::Version));
        }

        #[test]
        fn rejects_other_key_type() {
            let record = "v=IDMX1; k=rsa; p=".parse::<KeyRecord>();

            assert_eq!(record, Err(KeyRecordError::KeyType));
        }

        #[test]
        fn rejects_missing_p() {
            let record = "v=IDMX1; k=ed25519".parse::<KeyRecord>();

            assert_eq!(record, Err(KeyRecordError::MissingKey));
        }

        #[test]
        fn rejects_key_of_wrong_length() {
            let record = "v=IDMX1; k=ed25519; p=AAAA".parse::<KeyRecord>();

            assert_eq!(record, Err(KeyRecordError::InvalidKey));
        }
    }
}
