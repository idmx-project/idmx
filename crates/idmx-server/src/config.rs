//! The `idmxd` configuration file.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use idmx_core::domain::Domain;
use idmx_core::mailbox::Mailbox;
use serde::Deserialize;

/// Spec floor for `max_message_size` (`spec/delivery.md` §6): 25 MiB.
pub const MIN_MAX_MESSAGE_SIZE: usize = 26_214_400;
/// Spec floor and default for `max_recipients`.
pub const MIN_MAX_RECIPIENTS: usize = 100;

/// Errors from loading a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file is not valid TOML or has wrong field types.
    #[error(transparent)]
    Syntax(#[from] toml::de::Error),
    /// `authority` is not a lower-case `host[:port]`.
    #[error("authority `{0}` must be a lower-case host name with optional port")]
    Authority(String),
    /// A limit is below the floor the spec mandates.
    #[error("{name} must be at least {floor}")]
    BelowFloor {
        /// Name of the setting.
        name: &'static str,
        /// The smallest allowed value.
        floor: usize,
    },
    /// A mailbox is outside the served domain.
    #[error("mailbox `{0}` is not in the served domain")]
    ForeignMailbox(Mailbox),
    /// A mailbox needs an explicit `maildir` because its local part is not a
    /// safe directory name, or the given `maildir` is not a plain name.
    #[error("mailbox `{0}` needs a `maildir` that is a plain directory name")]
    Maildir(Mailbox),
    /// `abuse_contact` is not a `mailto:` URI without header fields.
    #[error("abuse_contact `{0}` must be a `mailto:` URI without `?`")]
    AbuseContact(String),
}

/// How the listener is secured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// `idmxd` terminates TLS 1.3 itself.
    Tls {
        /// PEM certificate chain.
        cert: PathBuf,
        /// PEM private key.
        key: PathBuf,
    },
    /// Plain HTTP/2 for a TLS-terminating reverse proxy in front.
    BehindProxy,
}

/// Validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The mail domain this receiver is responsible for.
    pub domain: Domain,
    /// `host[:port]` senders reach this receiver at: the expected `@authority`.
    pub authority: String,
    /// Socket to listen on.
    pub listen: SocketAddr,
    /// Directory for maildirs and the idempotency log.
    pub data_dir: PathBuf,
    /// TLS or plain.
    pub transport: Transport,
    /// Advertised `max_message_size`.
    pub max_message_size: usize,
    /// Advertised `max_recipients`.
    pub max_recipients: usize,
    /// Advertised `discovery_pin_max_age` in seconds.
    pub discovery_pin_max_age: u64,
    /// Advertised `abuse_contact`: a `mailto:` URI without header fields.
    pub abuse_contact: Option<String>,
    /// Known mailboxes and their maildir name below `data_dir/mail`.
    pub mailboxes: HashMap<Mailbox, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    domain: Domain,
    authority: String,
    listen: SocketAddr,
    data_dir: PathBuf,
    tls: Option<TlsFile>,
    max_message_size: Option<usize>,
    max_recipients: Option<usize>,
    discovery_pin_max_age: Option<u64>,
    abuse_contact: Option<String>,
    #[serde(default)]
    mailbox: Vec<MailboxFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFile {
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailboxFile {
    address: Mailbox,
    maildir: Option<String>,
}

impl Config {
    /// Parses and validates the TOML text of a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for syntax errors and rejected values.
    pub fn parse(toml_text: &str) -> Result<Self, ConfigError> {
        let file: ConfigFile = toml::from_str(toml_text)?;

        if !is_authority(&file.authority) {
            return Err(ConfigError::Authority(file.authority));
        }
        let max_message_size = at_least(
            "max_message_size",
            file.max_message_size,
            MIN_MAX_MESSAGE_SIZE,
        )?;
        let max_recipients = at_least("max_recipients", file.max_recipients, MIN_MAX_RECIPIENTS)?;
        if let Some(contact) = &file.abuse_contact
            && !is_abuse_contact(contact)
        {
            return Err(ConfigError::AbuseContact(contact.clone()));
        }

        let mut mailboxes = HashMap::with_capacity(file.mailbox.len());
        for MailboxFile { address, maildir } in file.mailbox {
            if address.domain() != &file.domain {
                return Err(ConfigError::ForeignMailbox(address));
            }
            let maildir = maildir.unwrap_or_else(|| address.local_part().to_owned());
            if !is_plain_name(&maildir) {
                return Err(ConfigError::Maildir(address));
            }
            mailboxes.insert(address, maildir);
        }

        Ok(Self {
            domain: file.domain,
            authority: file.authority,
            listen: file.listen,
            data_dir: file.data_dir,
            transport: file
                .tls
                .map_or(Transport::BehindProxy, |tls| Transport::Tls {
                    cert: tls.cert,
                    key: tls.key,
                }),
            max_message_size,
            max_recipients,
            discovery_pin_max_age: file.discovery_pin_max_age.unwrap_or(0),
            abuse_contact: file.abuse_contact,
            mailboxes,
        })
    }

    /// Host part of [`Self::authority`]: the `by` host and authserv-id.
    #[must_use]
    pub fn hostname(&self) -> &str {
        self.authority
            .split_once(':')
            .map_or(self.authority.as_str(), |(host, _)| host)
    }

    /// Root of all maildirs.
    #[must_use]
    pub fn mail_root(&self) -> PathBuf {
        self.data_dir.join("mail")
    }

    /// Path of the idempotency log.
    #[must_use]
    pub fn idempotency_log(&self) -> PathBuf {
        self.data_dir.join("idempotency.jsonl")
    }
}

fn at_least(name: &'static str, value: Option<usize>, floor: usize) -> Result<usize, ConfigError> {
    match value {
        Some(value) if value < floor => Err(ConfigError::BelowFloor { name, floor }),
        Some(value) => Ok(value),
        None => Ok(floor),
    }
}

fn is_authority(authority: &str) -> bool {
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    host.parse::<Domain>()
        .is_ok_and(|domain| domain.as_str() == host)
        && port.is_none_or(|port| port.parse::<u16>().is_ok())
}

/// `spec/capabilities.md` §3: a `mailto:` URI without header fields.
fn is_abuse_contact(contact: &str) -> bool {
    contact
        .strip_prefix("mailto:")
        .is_some_and(|address| address.contains('@') && !address.contains('?'))
}

/// A single path component that cannot escape the mail root.
fn is_plain_name(name: &str) -> bool {
    !name.starts_with('.')
        && Path::new(name).components().count() == 1
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        domain = "receiver.example"
        authority = "idmx.receiver.example:8443"
        listen = "127.0.0.1:8443"
        data_dir = "/var/lib/idmxd"
    "#;

    fn with(extra: &str) -> Result<Config, ConfigError> {
        Config::parse(&format!("{MINIMAL}\n{extra}"))
    }

    #[test]
    fn parse_should_default_limits_to_spec_floors() {
        let config = with("").unwrap();

        assert_eq!(
            (config.max_message_size, config.max_recipients),
            (MIN_MAX_MESSAGE_SIZE, MIN_MAX_RECIPIENTS)
        );
    }

    #[test]
    fn parse_should_default_to_proxy_transport_without_tls_section() {
        assert_eq!(with("").unwrap().transport, Transport::BehindProxy);
    }

    #[test]
    fn parse_should_accept_mailto_abuse_contact() {
        let config = with(r#"abuse_contact = "mailto:abuse@receiver.example""#).unwrap();

        assert_eq!(
            config.abuse_contact.as_deref(),
            Some("mailto:abuse@receiver.example")
        );
    }

    #[test]
    fn parse_should_reject_abuse_contact_with_header_fields() {
        let result = with(r#"abuse_contact = "mailto:abuse@receiver.example?subject=x""#);

        assert!(matches!(result, Err(ConfigError::AbuseContact(_))));
    }

    #[test]
    fn hostname_should_strip_port() {
        assert_eq!(with("").unwrap().hostname(), "idmx.receiver.example");
    }

    #[test]
    fn parse_should_fail_when_max_message_size_below_floor() {
        let result = with("max_message_size = 1000");

        assert!(
            matches!(
                result,
                Err(ConfigError::BelowFloor {
                    name: "max_message_size",
                    ..
                })
            ),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn parse_should_fail_when_authority_has_upper_case() {
        let result = Config::parse(&MINIMAL.replace("idmx.receiver", "IDMX.receiver"));

        assert!(
            matches!(result, Err(ConfigError::Authority(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn parse_should_use_local_part_as_default_maildir() {
        let config = with("[[mailbox]]\naddress = \"bob@receiver.example\"").unwrap();

        assert_eq!(
            config.mailboxes.values().next().map(String::as_str),
            Some("bob")
        );
    }

    #[test]
    fn parse_should_fail_when_mailbox_in_other_domain() {
        let result = with("[[mailbox]]\naddress = \"bob@other.example\"");

        assert!(
            matches!(result, Err(ConfigError::ForeignMailbox(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn parse_should_fail_when_local_part_is_not_a_safe_directory_name() {
        let result = with("[[mailbox]]\naddress = \"a/b@receiver.example\"");

        assert!(
            matches!(result, Err(ConfigError::Maildir(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn parse_should_fail_when_maildir_escapes_mail_root() {
        let result = with("[[mailbox]]\naddress = \"bob@receiver.example\"\nmaildir = \"../bob\"");

        assert!(
            matches!(result, Err(ConfigError::Maildir(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn parse_should_fail_on_unknown_setting() {
        let result = with("max_mesage_size = 1");

        assert!(
            matches!(result, Err(ConfigError::Syntax(_))),
            "unexpected: {result:?}"
        );
    }
}
