//! Trace headers the receiver prepends (`spec/signing.md` §8).

use std::time::SystemTime;

use idmx_core::idempotency::IdempotencyKey;
use idmx_core::mailbox::Mailbox;
use idmx_core::signing::VerifiedSignature;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

/// Facts about one accepted delivery that go into the trace headers.
#[derive(Debug, Clone, Copy)]
pub struct Trace<'a> {
    /// The verified transport signature.
    pub signature: &'a VerifiedSignature,
    /// This receiver's host name: `by` host and authserv-id.
    pub hostname: &'a str,
    /// The delivery's idempotency key.
    pub idempotency_key: &'a IdempotencyKey,
    /// The only recipient, if the delivery had exactly one.
    pub sole_recipient: Option<&'a Mailbox>,
    /// Time of receipt.
    pub received_at: SystemTime,
}

/// Returns `message` with `Received` and `Authentication-Results` prepended
/// and any pre-existing `Authentication-Results` claiming this receiver's
/// authserv-id removed (RFC 8601 §5).
#[must_use]
pub fn add_trace_headers(message: &[u8], trace: &Trace<'_>) -> Vec<u8> {
    let headers = render(trace);
    let mut output = Vec::with_capacity(headers.len() + message.len());
    output.extend_from_slice(headers.as_bytes());

    let mut rest = message;
    while let Some((field, after)) = next_header_field(rest) {
        if !is_forged_result(field, trace.hostname) {
            output.extend_from_slice(field);
        }
        rest = after;
    }
    output.extend_from_slice(rest);
    output
}

fn render(trace: &Trace<'_>) -> String {
    let Trace {
        signature,
        hostname,
        idempotency_key,
        sole_recipient,
        received_at,
    } = trace;
    let domain = signature.signing_domain();
    let selector = signature.keyid().selector();
    let date = OffsetDateTime::from(*received_at)
        .format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_owned());
    let recipient =
        sole_recipient.map_or_else(String::new, |mailbox| format!("\r\n    for <{mailbox}>"));

    format!(
        "Received: from {domain} by {hostname} with IDMX\r\n    id {idempotency_key}{recipient}; {date}\r\n\
         Authentication-Results: {hostname};\r\n    idmx=pass header.d={domain} header.s={selector}\r\n"
    )
}

/// Splits the first header field (with its folded continuation lines) off
/// `message`. `None` at the blank line that ends the header section, or when
/// the remainder is not a header field.
fn next_header_field(message: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = message.first()?;
    if matches!(first, b'\r' | b'\n' | b' ' | b'\t') {
        return None;
    }

    let mut end = 0;
    loop {
        end += message[end..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(message.len() - end, |newline| newline + 1);
        if !matches!(message.get(end), Some(b' ' | b'\t')) {
            break;
        }
    }
    let field = &message[..end];
    field.contains(&b':').then_some((field, &message[end..]))
}

/// Whether `field` is an `Authentication-Results` header using our authserv-id.
fn is_forged_result(field: &[u8], hostname: &str) -> bool {
    let Ok(field) = std::str::from_utf8(field) else {
        return false;
    };
    let Some((name, value)) = field.split_once(':') else {
        return false;
    };
    let authserv_id = value
        .trim_start()
        .split(|c: char| c == ';' || c.is_whitespace())
        .next()
        .unwrap_or_default();
    name.trim().eq_ignore_ascii_case("authentication-results")
        && authserv_id.eq_ignore_ascii_case(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_header_field_should_include_folded_lines() {
        let message = b"A: 1\r\n  folded\r\nB: 2\r\n\r\nbody";

        let (field, _) = next_header_field(message).unwrap();

        assert_eq!(field, b"A: 1\r\n  folded\r\n");
    }

    #[test]
    fn next_header_field_should_stop_at_blank_line() {
        assert_eq!(next_header_field(b"\r\nbody"), None);
    }

    #[test]
    fn is_forged_result_should_match_own_authserv_id_case_insensitively() {
        let field = b"authentication-results: IDMX.Receiver.Example; idmx=pass\r\n";

        assert!(is_forged_result(field, "idmx.receiver.example"));
    }

    #[test]
    fn is_forged_result_should_keep_results_of_other_hosts() {
        let field = b"Authentication-Results: mx.other.example; dkim=pass\r\n";

        assert!(!is_forged_result(field, "idmx.receiver.example"));
    }
}
