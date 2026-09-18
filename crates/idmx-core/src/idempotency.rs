//! The `Idempotency-Key` header value (`spec/delivery.md` §4).

use std::fmt;
use std::str::FromStr;

const MAX_LEN: usize = 128;

/// Error from parsing an [`IdempotencyKey`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("idempotency key must be 1-128 characters of A-Z a-z 0-9 . _ ~ -")]
pub struct IdempotencyKeyError;

/// A sender-chosen token identifying one delivery across retries:
/// 1–128 characters of `A-Z a-z 0-9 . _ ~ -`.
///
/// # Examples
///
/// ```
/// use idmx_core::idempotency::IdempotencyKey;
///
/// let key: IdempotencyKey = "01J8ZQ4M9X6T3V5B7N2K0HCDEF".parse()?;
/// assert_eq!(key.as_str(), "01J8ZQ4M9X6T3V5B7N2K0HCDEF");
/// # Ok::<(), idmx_core::idempotency::IdempotencyKeyError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// The key as sent in the header.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for IdempotencyKey {
    type Err = IdempotencyKeyError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte);
        if key.is_empty() || key.len() > MAX_LEN || !key.bytes().all(allowed) {
            return Err(IdempotencyKeyError);
        }
        Ok(Self(key.to_owned()))
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_should_accept_uuid() {
        let result = "0190f3a2-7c3e-7b1a-9d2e-5f6a7b8c9d0e".parse::<IdempotencyKey>();

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn parse_should_accept_128_characters() {
        let result = "a".repeat(128).parse::<IdempotencyKey>();

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn parse_should_fail_when_empty() {
        assert_eq!("".parse::<IdempotencyKey>(), Err(IdempotencyKeyError));
    }

    #[test]
    fn parse_should_fail_when_longer_than_128() {
        assert_eq!(
            "a".repeat(129).parse::<IdempotencyKey>(),
            Err(IdempotencyKeyError)
        );
    }

    #[test]
    fn parse_should_fail_when_character_not_allowed() {
        assert_eq!(
            "key with space".parse::<IdempotencyKey>(),
            Err(IdempotencyKeyError)
        );
    }
}
