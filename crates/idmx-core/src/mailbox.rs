//! Mailbox addresses (`spec/delivery.md` §3.1).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::domain::{Domain, DomainError};

const MAX_LOCAL_PART_LEN: usize = 64;

/// Errors from parsing a [`Mailbox`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MailboxError {
    /// The address contains no `@`.
    #[error("mailbox has no `@`")]
    MissingAt,
    /// The local part is empty, longer than 64 octets, or has control characters.
    #[error("mailbox local part is empty, too long, or contains control characters")]
    LocalPart,
    /// The part after the last `@` is not a valid domain.
    #[error("mailbox domain is invalid: {0}")]
    Domain(#[from] DomainError),
}

/// A `<local-part>@<domain>` address. The local part is opaque to everyone but
/// the receiving domain and compared byte for byte; the domain is normalized.
///
/// # Examples
///
/// ```
/// use idmx_core::mailbox::Mailbox;
///
/// let mailbox: Mailbox = "Alice@Sender.Example".parse()?;
/// assert_eq!(mailbox.local_part(), "Alice");
/// assert_eq!(mailbox.domain().as_str(), "sender.example");
/// # Ok::<(), idmx_core::mailbox::MailboxError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Mailbox {
    local_part: String,
    domain: Domain,
}

impl Mailbox {
    /// The part before the last `@`.
    #[must_use]
    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    /// The part after the last `@`.
    #[must_use]
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

impl FromStr for Mailbox {
    type Err = MailboxError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        let (local_part, domain) = address.rsplit_once('@').ok_or(MailboxError::MissingAt)?;
        if local_part.is_empty()
            || local_part.len() > MAX_LOCAL_PART_LEN
            || local_part.chars().any(char::is_control)
        {
            return Err(MailboxError::LocalPart);
        }
        Ok(Self {
            local_part: local_part.to_owned(),
            domain: domain.parse()?,
        })
    }
}

impl TryFrom<String> for Mailbox {
    type Error = MailboxError;

    fn try_from(address: String) -> Result<Self, Self::Error> {
        address.parse()
    }
}

impl From<Mailbox> for String {
    fn from(mailbox: Mailbox) -> Self {
        mailbox.to_string()
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_should_split_at_last_at_sign() {
        let mailbox: Mailbox = "\"odd@local\"@sender.example".parse().unwrap();

        assert_eq!(mailbox.local_part(), "\"odd@local\"");
    }

    #[test]
    fn parse_should_keep_local_part_case_and_fold_domain() {
        let mailbox: Mailbox = "Alice@Sender.EXAMPLE".parse().unwrap();

        assert_eq!(mailbox.to_string(), "Alice@sender.example");
    }

    #[test]
    fn parse_should_accept_utf8_local_part() {
        let result = "jürgen@sender.example".parse::<Mailbox>();

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn parse_should_fail_when_at_sign_missing() {
        assert_eq!("alice".parse::<Mailbox>(), Err(MailboxError::MissingAt));
    }

    #[test]
    fn parse_should_fail_when_local_part_empty() {
        assert_eq!(
            "@sender.example".parse::<Mailbox>(),
            Err(MailboxError::LocalPart)
        );
    }

    #[test]
    fn parse_should_fail_when_local_part_exceeds_64_octets() {
        let address = format!("{}@sender.example", "a".repeat(65));

        assert_eq!(address.parse::<Mailbox>(), Err(MailboxError::LocalPart));
    }

    #[test]
    fn parse_should_fail_when_local_part_has_control_character() {
        assert_eq!(
            "a\r\nb@sender.example".parse::<Mailbox>(),
            Err(MailboxError::LocalPart)
        );
    }

    #[test]
    fn parse_should_fail_when_domain_invalid() {
        let result = "alice@bad_domain".parse::<Mailbox>();

        assert_eq!(result, Err(MailboxError::Domain(DomainError::Character)));
    }

    #[test]
    fn deserialize_should_validate() {
        let result = serde_json::from_str::<Mailbox>("\"no-at-sign\"");

        assert!(result.is_err(), "unexpected: {result:?}");
    }

    #[test]
    fn serialize_should_render_address_string() {
        let mailbox: Mailbox = "bob@receiver.example".parse().unwrap();

        assert_eq!(
            serde_json::to_string(&mailbox).unwrap(),
            "\"bob@receiver.example\""
        );
    }
}
