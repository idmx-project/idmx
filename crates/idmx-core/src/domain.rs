//! The DNS domain: IDMX's unit of identity, routing, and policy.

use std::fmt;
use std::str::FromStr;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Errors from parsing a [`Domain`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    /// The name is empty or longer than 253 characters.
    #[error("domain name is empty or too long")]
    Length,
    /// A label is empty (leading, trailing, or doubled dot) or longer than 63 characters.
    #[error("domain name has an empty or over-long label")]
    Label,
    /// A label has a character outside `a-z`, `0-9`, `-`, or a hyphen at its
    /// edge. Internationalized names must be converted to A-labels first.
    #[error("domain name has a character that is not allowed in a host name")]
    Character,
}

/// A host-name-syntax DNS domain in IDNA A-label form: lower case, no trailing
/// dot. The part after the `@`, and the signing domain of a key.
///
/// # Examples
///
/// ```
/// use idmx_core::domain::Domain;
///
/// let domain: Domain = "Sender.Example".parse()?;
/// assert_eq!(domain.as_str(), "sender.example");
/// # Ok::<(), idmx_core::domain::DomainError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    /// The domain as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = DomainError;

    /// Validates `name` and folds it to lower case.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() || name.len() > MAX_DOMAIN_LEN {
            return Err(DomainError::Length);
        }
        name.split('.').try_for_each(check_label)?;
        Ok(Self(name.to_ascii_lowercase()))
    }
}

fn check_label(label: &str) -> Result<(), DomainError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(DomainError::Label);
    }
    let allowed = label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if !allowed || label.starts_with('-') || label.ends_with('-') {
        return Err(DomainError::Character);
    }
    Ok(())
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_to_lower_case() {
        let domain: Domain = "Sender.EXAMPLE".parse().unwrap();

        assert_eq!(domain.as_str(), "sender.example");
    }

    #[test]
    fn accepts_a_label_form() {
        let result = "xn--mnchen-3ya.example".parse::<Domain>();

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn rejects_empty_name() {
        assert_eq!("".parse::<Domain>(), Err(DomainError::Length));
    }

    #[test]
    fn rejects_trailing_dot() {
        assert_eq!("sender.example.".parse::<Domain>(), Err(DomainError::Label));
    }

    #[test]
    fn rejects_label_longer_than_63() {
        let name = format!("{}.example", "a".repeat(64));

        assert_eq!(name.parse::<Domain>(), Err(DomainError::Label));
    }

    #[test]
    fn rejects_unicode() {
        assert_eq!(
            "münchen.example".parse::<Domain>(),
            Err(DomainError::Character)
        );
    }

    #[test]
    fn rejects_underscore_label() {
        assert_eq!(
            "_idmx.example".parse::<Domain>(),
            Err(DomainError::Character)
        );
    }

    #[test]
    fn rejects_hyphen_at_label_edge() {
        assert_eq!("-a.example".parse::<Domain>(), Err(DomainError::Character));
    }
}
