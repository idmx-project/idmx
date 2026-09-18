//! The delivery envelope (`spec/delivery.md` §3).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::domain::Domain;
use crate::mailbox::Mailbox;

/// Errors from building an [`Envelope`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `to` is empty.
    #[error("envelope has no recipients")]
    NoRecipients,
    /// A recipient is listed twice.
    #[error("recipient `{0}` is listed more than once")]
    DuplicateRecipient(Mailbox),
    /// Recipients belong to more than one domain.
    #[error("recipient `{0}` is not in the same domain as the first recipient")]
    MixedDomains(Mailbox),
}

/// The envelope sender: where bounces go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Option<Mailbox>", into = "Option<Mailbox>")]
pub enum ReversePath {
    /// A regular sender. Its domain must equal the signing domain.
    Mailbox(Mailbox),
    /// The null reverse-path (`"from": null`), used by DSNs.
    Null,
}

impl From<Option<Mailbox>> for ReversePath {
    fn from(mailbox: Option<Mailbox>) -> Self {
        mailbox.map_or(Self::Null, Self::Mailbox)
    }
}

impl From<ReversePath> for Option<Mailbox> {
    fn from(reverse_path: ReversePath) -> Self {
        match reverse_path {
            ReversePath::Mailbox(mailbox) => Some(mailbox),
            ReversePath::Null => None,
        }
    }
}

/// A valid envelope: at least one recipient, no duplicates, one recipient domain.
///
/// # Examples
///
/// ```
/// use idmx_core::envelope::{Envelope, ReversePath};
///
/// let envelope = Envelope::new(
///     ReversePath::Mailbox("alice@sender.example".parse()?),
///     vec!["bob@receiver.example".parse()?],
/// )?;
/// assert_eq!(envelope.recipient_domain().as_str(), "receiver.example");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EnvelopeWire")]
pub struct Envelope {
    from: ReversePath,
    to: Vec<Mailbox>,
}

/// Unvalidated JSON shape; unknown fields are ignored.
#[derive(Deserialize)]
struct EnvelopeWire {
    // serde defaults a missing `Option`-like field to `None`; going through
    // `deserialize_with` keeps `from` required while still allowing `null`.
    #[serde(deserialize_with = "required_reverse_path")]
    from: ReversePath,
    to: Vec<Mailbox>,
}

fn required_reverse_path<'de, D>(deserializer: D) -> Result<ReversePath, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Mailbox>::deserialize(deserializer).map(ReversePath::from)
}

impl TryFrom<EnvelopeWire> for Envelope {
    type Error = EnvelopeError;

    fn try_from(wire: EnvelopeWire) -> Result<Self, Self::Error> {
        Self::new(wire.from, wire.to)
    }
}

impl Envelope {
    /// Validates the recipient list.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] if `to` is empty, has duplicates, or spans
    /// more than one domain.
    pub fn new(from: ReversePath, to: Vec<Mailbox>) -> Result<Self, EnvelopeError> {
        let first = to.first().ok_or(EnvelopeError::NoRecipients)?;
        let mut seen = HashSet::with_capacity(to.len());
        for recipient in &to {
            if recipient.domain() != first.domain() {
                return Err(EnvelopeError::MixedDomains(recipient.clone()));
            }
            if !seen.insert(recipient) {
                return Err(EnvelopeError::DuplicateRecipient(recipient.clone()));
            }
        }
        Ok(Self { from, to })
    }

    /// The envelope sender.
    #[must_use]
    pub fn from(&self) -> &ReversePath {
        &self.from
    }

    /// The recipients; never empty, all in [`Self::recipient_domain`].
    #[must_use]
    pub fn to(&self) -> &[Mailbox] {
        &self.to
    }

    /// The domain this delivery is addressed to.
    #[must_use]
    pub fn recipient_domain(&self) -> &Domain {
        // `new` guarantees at least one recipient.
        self.to[0].domain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(address: &str) -> Mailbox {
        address.parse().unwrap()
    }

    #[test]
    fn new_should_fail_when_no_recipients() {
        let result = Envelope::new(ReversePath::Null, vec![]);

        assert_eq!(result, Err(EnvelopeError::NoRecipients));
    }

    #[test]
    fn new_should_fail_when_recipient_duplicated() {
        let to = vec![
            mailbox("bob@receiver.example"),
            mailbox("bob@Receiver.Example"),
        ];

        let result = Envelope::new(ReversePath::Null, to);

        assert_eq!(
            result,
            Err(EnvelopeError::DuplicateRecipient(mailbox(
                "bob@receiver.example"
            )))
        );
    }

    #[test]
    fn new_should_fail_when_recipient_domains_differ() {
        let to = vec![
            mailbox("bob@receiver.example"),
            mailbox("carol@other.example"),
        ];

        let result = Envelope::new(ReversePath::Null, to);

        assert_eq!(
            result,
            Err(EnvelopeError::MixedDomains(mailbox("carol@other.example")))
        );
    }

    #[test]
    fn deserialize_should_read_null_from_as_null_reverse_path() {
        let envelope: Envelope =
            serde_json::from_str(r#"{"from":null,"to":["bob@receiver.example"]}"#).unwrap();

        assert_eq!(envelope.from(), &ReversePath::Null);
    }

    #[test]
    fn deserialize_should_fail_when_from_missing() {
        let result = serde_json::from_str::<Envelope>(r#"{"to":["bob@receiver.example"]}"#);

        assert!(result.is_err(), "unexpected: {result:?}");
    }

    #[test]
    fn deserialize_should_ignore_unknown_fields() {
        let json = r#"{"from":null,"to":["bob@receiver.example"],"attestations":[1]}"#;

        let result = serde_json::from_str::<Envelope>(json);

        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn deserialize_should_validate_recipients() {
        let result = serde_json::from_str::<Envelope>(r#"{"from":null,"to":[]}"#);

        assert!(result.is_err(), "unexpected: {result:?}");
    }

    #[test]
    fn serialize_should_write_null_reverse_path_as_null() {
        let envelope = Envelope::new(ReversePath::Null, vec![mailbox("bob@receiver.example")]);

        let json = serde_json::to_string(&envelope.unwrap()).unwrap();

        assert_eq!(json, r#"{"from":null,"to":["bob@receiver.example"]}"#);
    }
}
