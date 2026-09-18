//! Bounces: an RFC 3464 delivery status notification for recipients the
//! sender has given up on (`spec/errors.md` §6). The DSN is an ordinary
//! message with the null reverse-path; the caller queues it like any other.

use std::fmt::{self, Write as _};
use std::time::SystemTime;

use idmx_core::domain::Domain;
use idmx_core::mailbox::Mailbox;
use idmx_core::problem::{Problem, ProblemKind, ProblemType};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

/// Why delivery failed for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// The receiver rejected the request or the recipient permanently.
    Rejected(Problem),
    /// Temporary failures lasted until the give-up time.
    GaveUp,
}

impl FailureReason {
    /// The RFC 3463 enhanced status code reported in the DSN.
    fn status(&self) -> &'static str {
        let kind = match self {
            Self::GaveUp => return "4.4.7",
            Self::Rejected(problem) => match &problem.problem_type {
                ProblemType::Known(kind) => *kind,
                ProblemType::Other(_) => return "5.0.0",
            },
        };
        match kind {
            ProblemKind::RecipientNotFound => "5.1.1",
            ProblemKind::MailboxFull => "5.2.2",
            ProblemKind::MessageTooLarge => "5.3.4",
            ProblemKind::PolicyRejected | ProblemKind::InvalidSignature => "5.7.1",
            ProblemKind::InvalidRequest
            | ProblemKind::UnsupportedVersion
            | ProblemKind::IdempotencyConflict
            | ProblemKind::UnsupportedFeature
            | ProblemKind::RateLimited
            | ProblemKind::TemporaryFailure => "5.0.0",
        }
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GaveUp => f.write_str("gave up after the retry period"),
            Self::Rejected(problem) => {
                write!(f, "{}", problem.problem_type)?;
                match &problem.detail {
                    Some(detail) => write!(f, " ({})", one_line(detail)),
                    None => Ok(()),
                }
            }
        }
    }
}

/// What a DSN reports.
#[derive(Debug)]
pub struct Report<'a> {
    /// The sending domain; it reports the failure.
    pub reporting_domain: &'a Domain,
    /// The envelope sender of the failed message; the DSN goes here.
    pub original_sender: &'a Mailbox,
    /// The recipients that failed.
    pub recipients: &'a [Mailbox],
    /// Why they failed.
    pub reason: &'a FailureReason,
    /// The failed message; its header section is returned.
    pub message: &'a [u8],
}

/// Renders the DSN. `unique` must differ per DSN (an idempotency key will
/// do): it becomes the `Message-ID` and the MIME boundary.
#[must_use]
pub fn render(report: &Report<'_>, unique: &str, now: SystemTime) -> Vec<u8> {
    let Report {
        reporting_domain,
        original_sender,
        recipients,
        reason,
        message,
    } = report;
    let date = OffsetDateTime::from(now)
        .format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_owned());
    let boundary = format!("idmx-dsn-{unique}");
    let status = reason.status();

    let mut text = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{reporting_domain}>\r\n\
         To: <{original_sender}>\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         Date: {date}\r\n\
         Message-ID: <{unique}@{reporting_domain}>\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n    boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is the mail system of {reporting_domain}.\r\n\
         \r\n\
         Your message could not be delivered to the recipients below.\r\n\
         Reason: {reason}\r\n\
         \r\n"
    );
    // Writing to a `String` cannot fail.
    for recipient in *recipients {
        let _ = write!(text, "    <{recipient}>\r\n");
    }
    let _ = write!(
        text,
        "\r\n--{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {reporting_domain}\r\n"
    );
    for recipient in *recipients {
        let _ = write!(
            text,
            "\r\n\
             Final-Recipient: rfc822; {recipient}\r\n\
             Action: failed\r\n\
             Status: {status}\r\n\
             Diagnostic-Code: x-idmx; {reason}\r\n"
        );
    }
    let _ = write!(
        text,
        "\r\n--{boundary}\r\nContent-Type: text/rfc822-headers\r\n\r\n"
    );

    let mut dsn = text.into_bytes();
    dsn.extend_from_slice(header_section(message));
    dsn.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    dsn
}

/// The header section of `message`, without the blank line that ends it.
fn header_section(message: &[u8]) -> &[u8] {
    let end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| message.windows(2).position(|window| window == b"\n\n"));
    end.map_or(message, |end| &message[..end])
}

/// Receiver-supplied text must not break out of its header field.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(reason: &FailureReason) -> String {
        let report = Report {
            reporting_domain: &"sender.example".parse().unwrap(),
            original_sender: &"alice@sender.example".parse().unwrap(),
            recipients: &["nobody@receiver.example".parse().unwrap()],
            reason,
            message: b"Subject: Hello\r\nFrom: alice@sender.example\r\n\r\nsecret body\r\n",
        };
        String::from_utf8(render(&report, "k1", SystemTime::UNIX_EPOCH)).unwrap()
    }

    fn rejected(kind: ProblemKind) -> FailureReason {
        FailureReason::Rejected(Problem::new(kind))
    }

    #[test]
    fn render_should_address_the_original_sender() {
        let dsn = rendered(&FailureReason::GaveUp);

        assert!(dsn.contains("\r\nTo: <alice@sender.example>\r\n"), "{dsn}");
    }

    #[test]
    fn render_should_report_each_failed_recipient() {
        let dsn = rendered(&rejected(ProblemKind::RecipientNotFound));

        assert!(
            dsn.contains(
                "Final-Recipient: rfc822; nobody@receiver.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"
            ),
            "{dsn}"
        );
    }

    #[test]
    fn render_should_report_expired_delivery_time_when_given_up() {
        let dsn = rendered(&FailureReason::GaveUp);

        assert!(dsn.contains("Status: 4.4.7\r\n"), "{dsn}");
    }

    #[test]
    fn render_should_return_headers_without_the_body() {
        let dsn = rendered(&FailureReason::GaveUp);

        assert!(
            dsn.contains("Subject: Hello\r\n") && !dsn.contains("secret body"),
            "{dsn}"
        );
    }

    #[test]
    fn render_should_keep_receiver_detail_on_one_line() {
        let problem = Problem::new(ProblemKind::PolicyRejected).with_detail("no\r\nBcc: x");
        let dsn = rendered(&FailureReason::Rejected(problem));

        assert!(!dsn.contains("\r\nBcc:"), "{dsn}");
    }
}
