//! The `multipart/mixed` request body (`spec/delivery.md` §2): part 1 is the
//! JSON envelope, part 2 the raw RFC 5322 message.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use sha2::{Digest as _, Sha256};

use crate::envelope::Envelope;

const ENVELOPE_TYPE: &str = "application/json";
const MESSAGE_TYPE: &str = "message/rfc822";
const CRLF: &[u8] = b"\r\n";

/// Errors from [`decode`]. All map to `invalid_request`.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    /// `Content-Type` is not `multipart/mixed` with a usable `boundary`.
    #[error("content type is not multipart/mixed with a boundary parameter")]
    ContentType,
    /// The body does not follow multipart syntax for the given boundary.
    #[error("body is not well-formed multipart data")]
    Malformed,
    /// The body does not have exactly two parts.
    #[error("body has {0} parts, expected 2")]
    PartCount(usize),
    /// A part does not have the required `Content-Type`.
    #[error("part {index} must have content type {expected}")]
    PartType {
        /// 1-based part number.
        index: usize,
        /// The media type the spec requires there.
        expected: &'static str,
    },
    /// Part 1 is not a valid envelope.
    #[error("envelope is invalid: {0}")]
    Envelope(#[source] serde_json::Error),
}

/// An encoded request body and the `Content-Type` header value that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBody {
    /// `multipart/mixed; boundary=…`
    pub content_type: String,
    /// The exact HTTP content; sign and send these bytes unchanged.
    pub bytes: Vec<u8>,
}

/// A decoded request body. `message` borrows from the input: the message is
/// passed on byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody<'a> {
    /// The validated envelope.
    pub envelope: Envelope,
    /// The raw RFC 5322 message.
    pub message: &'a [u8],
}

/// Encodes `envelope` and `message` as the two-part request body.
///
/// # Errors
///
/// Returns the JSON error if the envelope cannot be serialized.
pub fn encode(envelope: &Envelope, message: &[u8]) -> Result<EncodedBody, serde_json::Error> {
    let envelope = serde_json::to_vec(envelope)?;
    let boundary = choose_boundary(&envelope, message);

    let mut bytes = Vec::with_capacity(envelope.len() + message.len() + 256);
    for (content_type, content) in [
        (ENVELOPE_TYPE, envelope.as_slice()),
        (MESSAGE_TYPE, message),
    ] {
        bytes.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: {content_type}\r\n\r\n").as_bytes(),
        );
        bytes.extend_from_slice(content);
        bytes.extend_from_slice(CRLF);
    }
    bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Ok(EncodedBody {
        content_type: format!("multipart/mixed; boundary={boundary}"),
        bytes,
    })
}

/// Derives a boundary from the content, so encoding is deterministic, and
/// makes sure it does not occur in either part.
fn choose_boundary(envelope: &[u8], message: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(envelope);
    hasher.update(message);
    let mut digest = hasher.finalize();

    loop {
        let boundary = format!("idmx-{}", BASE64_URL.encode(&digest[..18]));
        let occurs = |part: &[u8]| find(part, boundary.as_bytes()).is_some();
        if !occurs(envelope) && !occurs(message) {
            return boundary;
        }
        digest = Sha256::digest(digest);
    }
}

/// Decodes a request body.
///
/// # Errors
///
/// Returns [`BodyError`] if the content type, multipart framing, part layout,
/// or envelope is invalid.
pub fn decode<'a>(content_type: &str, body: &'a [u8]) -> Result<DecodedBody<'a>, BodyError> {
    let boundary = boundary_of(content_type).ok_or(BodyError::ContentType)?;
    let parts = split_parts(body, boundary).ok_or(BodyError::Malformed)?;
    let [envelope, message] = parts.as_slice() else {
        return Err(BodyError::PartCount(parts.len()));
    };

    let envelope = content_of(envelope, 1, ENVELOPE_TYPE)?;
    let message = content_of(message, 2, MESSAGE_TYPE)?;
    Ok(DecodedBody {
        envelope: serde_json::from_slice(envelope).map_err(BodyError::Envelope)?,
        message,
    })
}

/// Extracts the `boundary` parameter of a `multipart/mixed` content type.
fn boundary_of(content_type: &str) -> Option<&str> {
    let mut params = content_type.split(';').map(str::trim);
    if !params.next()?.eq_ignore_ascii_case("multipart/mixed") {
        return None;
    }
    let boundary = params.find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"'))
    })?;
    (1..=70).contains(&boundary.len()).then_some(boundary)
}

/// Splits multipart data into its raw parts (headers + content), ignoring
/// preamble and epilogue. `None` if the framing is broken.
fn split_parts<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<&'a [u8]>> {
    let delimiter = [b"\r\n--", boundary.as_bytes()].concat();

    // The first delimiter may sit at the very start, without a preceding CRLF.
    let mut rest = match body.strip_prefix(&delimiter[CRLF.len()..]) {
        Some(rest) => rest,
        None => &body[find(body, &delimiter)? + delimiter.len()..],
    };

    let mut parts = Vec::new();
    loop {
        if rest.starts_with(b"--") {
            return Some(parts);
        }
        let line_end = find(rest, CRLF)?;
        if !rest[..line_end]
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t'))
        {
            return None;
        }
        // Keep the CRLF: a part without headers starts with the blank line.
        let part_start = &rest[line_end..];
        let part_len = find(part_start, &delimiter)?;
        parts.push(&part_start[..part_len]);
        rest = &part_start[part_len + delimiter.len()..];
    }
}

/// Returns a part's content after checking its `Content-Type` header.
fn content_of<'a>(
    part: &'a [u8],
    index: usize,
    expected: &'static str,
) -> Result<&'a [u8], BodyError> {
    let wrong_type = BodyError::PartType { index, expected };
    let Some(headers_len) = find(part, b"\r\n\r\n") else {
        return Err(wrong_type);
    };
    let headers = std::str::from_utf8(&part[..headers_len]).map_err(|_| BodyError::Malformed)?;

    let media_type = headers.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-type")
            .then(|| value.split(';').next().unwrap_or_default().trim())
    });
    if media_type.is_some_and(|media_type| media_type.eq_ignore_ascii_case(expected)) {
        Ok(&part[headers_len + 4..])
    } else {
        Err(wrong_type)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ReversePath;

    const CONTENT_TYPE: &str = "multipart/mixed; boundary=b";

    fn envelope() -> Envelope {
        Envelope::new(
            ReversePath::Null,
            vec!["bob@receiver.example".parse().unwrap()],
        )
        .unwrap()
    }

    fn body(parts: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (content_type, content) in parts {
            body.extend_from_slice(b"--b\r\nContent-Type: ");
            body.extend_from_slice(content_type.as_bytes());
            body.extend_from_slice(b"\r\n\r\n");
            body.extend_from_slice(content.as_bytes());
            body.extend_from_slice(CRLF);
        }
        body.extend_from_slice(b"--b--\r\n");
        body
    }

    const ENVELOPE_JSON: &str = r#"{"from":null,"to":["bob@receiver.example"]}"#;

    mod encode {
        use super::*;

        #[test]
        fn output_should_decode_to_same_envelope_and_message() {
            let message = b"Subject: hi\r\n\r\nbinary \x00\xff body\r\n";

            let encoded = encode(&envelope(), message).unwrap();
            let decoded = decode(&encoded.content_type, &encoded.bytes).unwrap();

            assert_eq!(
                (decoded.envelope, decoded.message),
                (envelope(), message.as_slice())
            );
        }

        #[test]
        fn output_should_be_deterministic() {
            let first = encode(&envelope(), b"message").unwrap();

            assert_eq!(encode(&envelope(), b"message").unwrap(), first);
        }

        #[test]
        fn boundary_should_not_occur_in_message() {
            let natural = choose_boundary(ENVELOPE_JSON.as_bytes(), b"");
            let message = format!("text --{natural} text");

            let boundary = choose_boundary(ENVELOPE_JSON.as_bytes(), message.as_bytes());

            assert!(
                !message.contains(&boundary),
                "boundary {boundary} occurs in message"
            );
        }
    }

    mod decode {
        use super::*;

        #[test]
        fn should_keep_message_bytes_including_trailing_crlf() {
            let body = body(&[
                (ENVELOPE_TYPE, ENVELOPE_JSON),
                (MESSAGE_TYPE, "A: b\r\n\r\ntext\r\n"),
            ]);

            let decoded = decode(CONTENT_TYPE, &body).unwrap();

            assert_eq!(decoded.message, b"A: b\r\n\r\ntext\r\n");
        }

        #[test]
        fn should_accept_quoted_boundary_and_ignore_preamble_and_epilogue() {
            let mut data = b"preamble\r\n".to_vec();
            data.extend(body(&[(ENVELOPE_TYPE, ENVELOPE_JSON), (MESSAGE_TYPE, "m")]));
            data.extend(b"epilogue");

            let result = decode("Multipart/Mixed; charset=x; boundary=\"b\"", &data);

            assert!(result.is_ok(), "unexpected: {result:?}");
        }

        #[test]
        fn should_fail_when_content_type_is_not_multipart_mixed() {
            let result = decode("application/json", b"{}");

            assert!(
                matches!(result, Err(BodyError::ContentType)),
                "unexpected: {result:?}"
            );
        }

        #[test]
        fn should_fail_when_boundary_parameter_missing() {
            let result = decode("multipart/mixed", b"");

            assert!(
                matches!(result, Err(BodyError::ContentType)),
                "unexpected: {result:?}"
            );
        }

        #[test]
        fn should_fail_when_close_delimiter_missing() {
            let mut body = body(&[(ENVELOPE_TYPE, ENVELOPE_JSON), (MESSAGE_TYPE, "m")]);
            body.truncate(body.len() - b"--b--\r\n".len());

            let result = decode(CONTENT_TYPE, &body);

            assert!(
                matches!(result, Err(BodyError::Malformed)),
                "unexpected: {result:?}"
            );
        }

        #[test]
        fn should_fail_when_third_part_present() {
            let body = body(&[
                (ENVELOPE_TYPE, ENVELOPE_JSON),
                (MESSAGE_TYPE, "m"),
                ("text/plain", "extra"),
            ]);

            let result = decode(CONTENT_TYPE, &body);

            assert!(
                matches!(result, Err(BodyError::PartCount(3))),
                "unexpected: {result:?}"
            );
        }

        #[test]
        fn should_fail_when_parts_are_swapped() {
            let body = body(&[(MESSAGE_TYPE, "m"), (ENVELOPE_TYPE, ENVELOPE_JSON)]);

            let result = decode(CONTENT_TYPE, &body);

            assert!(
                matches!(result, Err(BodyError::PartType { index: 1, .. })),
                "unexpected: {result:?}"
            );
        }

        #[test]
        fn should_fail_when_envelope_invalid() {
            let body = body(&[
                (ENVELOPE_TYPE, r#"{"from":null,"to":[]}"#),
                (MESSAGE_TYPE, "m"),
            ]);

            let result = decode(CONTENT_TYPE, &body);

            assert!(
                matches!(result, Err(BodyError::Envelope(_))),
                "unexpected: {result:?}"
            );
        }
    }
}
