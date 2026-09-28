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
    /// The local part is empty, longer than 64 octets, or not a dot-string or
    /// quoted-string.
    #[error("mailbox local part is empty, too long, or not a dot-string or quoted-string")]
    LocalPart,
    /// The local part is quoted or escaped where its minimal form is not.
    #[error("mailbox local part is not in minimal form")]
    NotMinimal,
    /// The part after the last `@` is not a valid domain.
    #[error("mailbox domain is invalid: {0}")]
    Domain(#[from] DomainError),
}

/// A `<local-part>@<domain>` address. The local part is kept in its minimal
/// SMTP written form, opaque to everyone but the receiving domain, and compared
/// byte for byte; the domain is normalized.
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
        check_local_part(local_part)?;
        Ok(Self {
            local_part: local_part.to_owned(),
            domain: domain.parse()?,
        })
    }
}

/// Checks `local_part` against the `Local-part` grammar and the minimal-form
/// rule of `spec/delivery.md` §3.1.
fn check_local_part(local_part: &str) -> Result<(), MailboxError> {
    if local_part.is_empty() || local_part.len() > MAX_LOCAL_PART_LEN {
        return Err(MailboxError::LocalPart);
    }
    let Some(quoted) = local_part.strip_prefix('"') else {
        return if is_dot_string(local_part) {
            Ok(())
        } else {
            Err(MailboxError::LocalPart)
        };
    };
    let inner = quoted.strip_suffix('"').ok_or(MailboxError::LocalPart)?;
    let mut content = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let escaped = chars.next().ok_or(MailboxError::LocalPart)?;
                if !matches!(escaped, ' '..='~') {
                    return Err(MailboxError::LocalPart);
                }
                if !matches!(escaped, '"' | '\\') {
                    return Err(MailboxError::NotMinimal);
                }
                content.push(escaped);
            }
            '"' => return Err(MailboxError::LocalPart),
            ' '..='~' => content.push(c),
            _ if is_utf8_non_ascii(c) => content.push(c),
            _ => return Err(MailboxError::LocalPart),
        }
    }
    if is_dot_string(&content) {
        return Err(MailboxError::NotMinimal);
    }
    Ok(())
}

/// `Atom *("." Atom)` with RFC 6531 UTF-8 in atoms.
fn is_dot_string(s: &str) -> bool {
    s.split('.')
        .all(|atom| !atom.is_empty() && atom.chars().all(|c| is_atext(c) || is_utf8_non_ascii(c)))
}

/// RFC 5322 `atext`.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c)
}

/// RFC 6532 `UTF8-non-ascii` without the C1 controls.
fn is_utf8_non_ascii(c: char) -> bool {
    !c.is_ascii() && !c.is_control()
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
    fn parse_should_accept_quoted_local_part_with_space_and_escapes() {
        let mailbox: Mailbox = r#""john \"j\\d\" doe"@sender.example"#.parse().unwrap();

        assert_eq!(mailbox.local_part(), r#""john \"j\\d\" doe""#);
    }

    #[test]
    fn parse_should_accept_dot_string_with_specials() {
        let result = "a.b+tag!#$%&'*/=?^_`{|}~-@sender.example".parse::<Mailbox>();

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn parse_should_fail_when_quoting_is_not_needed() {
        assert_eq!(
            "\"alice\"@sender.example".parse::<Mailbox>(),
            Err(MailboxError::NotMinimal)
        );
    }

    #[test]
    fn parse_should_fail_when_escape_is_not_needed() {
        assert_eq!(
            r#""a\ b"@sender.example"#.parse::<Mailbox>(),
            Err(MailboxError::NotMinimal)
        );
    }

    #[test]
    fn parse_should_fail_when_space_unquoted() {
        assert_eq!(
            "john doe@sender.example".parse::<Mailbox>(),
            Err(MailboxError::LocalPart)
        );
    }

    #[test]
    fn parse_should_fail_when_dots_misplaced() {
        for address in [".a@x.example", "a.@x.example", "a..b@x.example"] {
            assert_eq!(
                address.parse::<Mailbox>(),
                Err(MailboxError::LocalPart),
                "{address}"
            );
        }
    }

    #[test]
    fn parse_should_fail_when_quote_unterminated() {
        assert_eq!(
            "\"a b@sender.example".parse::<Mailbox>(),
            Err(MailboxError::LocalPart)
        );
    }

    #[test]
    fn parse_should_fail_when_local_part_has_c1_control() {
        assert_eq!(
            "a\u{85}b@sender.example".parse::<Mailbox>(),
            Err(MailboxError::LocalPart)
        );
    }

    #[test]
    fn parse_should_count_quotes_toward_64_octets() {
        let fits = format!("\"{}\"@sender.example", " ".repeat(62));
        let over = format!("\"{}\"@sender.example", " ".repeat(63));

        assert!(fits.parse::<Mailbox>().is_ok());
        assert_eq!(over.parse::<Mailbox>(), Err(MailboxError::LocalPart));
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
