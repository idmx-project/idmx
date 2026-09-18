//! Black-box conformance checks for IDMX receivers.
//!
//! [`run`] talks to a receiver over HTTP only and knows nothing about its
//! implementation. Without a [`DeliveryProbe`] it covers what needs no sender
//! identity: the capabilities document, version handling, transport, and the
//! rejection of unsigned deliveries. With one it also sends signed deliveries
//! (signature checks, request validation, idempotency, per-recipient results).

mod capabilities;
pub mod delivery;
pub mod report;

use std::str::FromStr;

use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE};
use reqwest::{Client, Response, StatusCode, Url, Version};
use serde_json::{Map, Value};

use crate::delivery::DeliveryProbe;
use crate::report::{Check, Level, Outcome, Report};

const PROBLEM_BASE: &str = "https://idmx-project.org/problems/";

/// The origin of a receiver: `https://host[:port]`, nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(Url);

/// Why a string is not an [`Origin`].
#[derive(Debug, thiserror::Error)]
#[error("expected an origin like https://idmx.example.org:8443")]
pub struct OriginError;

impl FromStr for Origin {
    type Err = OriginError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(text).map_err(|_| OriginError)?;
        let is_origin = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none();
        if is_origin {
            Ok(Self(url))
        } else {
            Err(OriginError)
        }
    }
}

impl Origin {
    /// Whether the origin is plain HTTP: only useful for testing a receiver
    /// behind its TLS proxy, with HTTP/2 prior knowledge.
    #[must_use]
    pub fn is_plain_http(&self) -> bool {
        self.0.scheme() == "http"
    }

    /// `host[:port]` as it appears in `@authority`: no port when it is the
    /// scheme's default.
    fn authority(&self) -> String {
        let host = self.0.host_str().unwrap_or_default();
        self.0
            .port()
            .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"))
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(path);
        url
    }
}

/// A `reqwest` client builder with the transport rules of `spec/discovery.md`
/// §4 applied: TLS 1.3 as the minimum.
pub fn http_client_builder() -> reqwest::ClientBuilder {
    // A failed install only means a provider is already in place.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder().tls_version_min(reqwest::tls::Version::TLS_1_3)
}

/// Runs every check against the receiver at `origin`; the signed ones only
/// with a `probe`. They deliver probe messages to the probe's recipient.
pub async fn run(http: &Client, origin: &Origin, probe: Option<&DeliveryProbe>) -> Report {
    let mut checks = check_capabilities(http, origin).await;
    checks.push(check_unknown_version(http, origin).await);
    checks.push(check_unsigned_delivery(http, origin).await);
    if let Some(probe) = probe {
        checks.extend(probe.run(http, origin).await);
    }
    Report { checks }
}

async fn check_capabilities(http: &Client, origin: &Origin) -> Vec<Check> {
    let fetch = |outcome| Check {
        id: "CAP-01",
        spec: "capabilities.md §3",
        level: Level::Must,
        requirement: "GET /v1/capabilities answers 200 with a JSON object",
        outcome,
    };
    let response = match http.get(origin.url("/v1/capabilities")).send().await {
        Ok(response) => response,
        Err(error) => return vec![fetch(Outcome::Fail(error.to_string()))],
    };

    let transport = Check {
        id: "TRN-01",
        spec: "discovery.md §4",
        level: Level::Must,
        requirement: "the receiver speaks HTTP/2",
        outcome: if response.version() == Version::HTTP_2 {
            Outcome::Pass
        } else {
            Outcome::Fail(format!("answered with {:?}", response.version()))
        },
    };
    let cache_control =
        capabilities::check_cache_control(header(&response, CACHE_CONTROL.as_str()));

    let status = response.status();
    let is_json = header(&response, CONTENT_TYPE.as_str()).is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    });
    let document = response.json::<Map<String, Value>>().await;

    let mut checks = vec![transport];
    match document {
        Ok(document) if status == StatusCode::OK && is_json => {
            checks.push(fetch(Outcome::Pass));
            checks.extend(capabilities::check_document(&document));
        }
        Ok(_) => checks.push(fetch(Outcome::Fail(format!(
            "status {status}, application/json: {is_json}"
        )))),
        Err(error) => checks.push(fetch(Outcome::Fail(error.to_string()))),
    }
    checks.push(cache_control);
    checks
}

async fn check_unknown_version(http: &Client, origin: &Origin) -> Check {
    let request = http.get(origin.url("/v4294967295/capabilities"));
    Check {
        id: "VER-01",
        spec: "errors.md §2",
        level: Level::Must,
        requirement: "a path under an unknown major version answers 404 unsupported_version",
        outcome: expect_problem(request, StatusCode::NOT_FOUND, "unsupported_version").await,
    }
}

async fn check_unsigned_delivery(http: &Client, origin: &Origin) -> Check {
    const BODY: &str = "--idmx-conformance\r\n\
        Content-Type: application/json\r\n\r\n\
        {\"from\":\"probe@conformance.invalid\",\"to\":[\"postmaster@conformance.invalid\"]}\r\n\
        --idmx-conformance\r\n\
        Content-Type: message/rfc822\r\n\r\n\
        Subject: IDMX conformance probe\r\n\r\nNot meant to be delivered.\r\n\r\n\
        --idmx-conformance--\r\n";
    let request = http
        .post(origin.url("/v1/messages"))
        .header(CONTENT_TYPE, "multipart/mixed; boundary=idmx-conformance")
        .header("idempotency-key", "idmx-conformance-unsigned")
        .body(BODY);
    Check {
        id: "SIG-01",
        spec: "signing.md §1",
        level: Level::Must,
        requirement: "an unsigned delivery answers 401 invalid_signature",
        outcome: expect_problem(request, StatusCode::UNAUTHORIZED, "invalid_signature").await,
    }
}

/// Sends `request` and expects an RFC 9457 problem of the given kind.
pub(crate) async fn expect_problem(
    request: reqwest::RequestBuilder,
    expected_status: StatusCode,
    expected_kind: &str,
) -> Outcome {
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return Outcome::Fail(error.to_string()),
    };
    let status = response.status();
    if status != expected_status {
        return Outcome::Fail(format!("status {status}"));
    }
    let media = header(&response, CONTENT_TYPE.as_str()).map(str::to_owned);
    if !media
        .as_deref()
        .is_some_and(|value| value.starts_with("application/problem+json"))
    {
        return Outcome::Fail(format!(
            "Content-Type: {}",
            media.as_deref().unwrap_or("<absent>")
        ));
    }
    let problem_type = response
        .json::<Map<String, Value>>()
        .await
        .ok()
        .and_then(|problem| problem.get("type")?.as_str().map(str::to_owned));
    match problem_type {
        Some(uri) if uri.strip_prefix(PROBLEM_BASE) == Some(expected_kind) => Outcome::Pass,
        Some(uri) => Outcome::Fail(format!("problem type {uri}")),
        None => Outcome::Fail("no problem document with a type".to_owned()),
    }
}

fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response.headers().get(name)?.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_should_parse_host_and_port() {
        assert!("https://idmx.example.org:8443".parse::<Origin>().is_ok());
    }

    #[test]
    fn origin_should_reject_path() {
        let result = "https://idmx.example.org/v1".parse::<Origin>();

        assert!(result.is_err());
    }

    #[test]
    fn origin_should_reject_other_schemes() {
        let result = "ftp://idmx.example.org".parse::<Origin>();

        assert!(result.is_err());
    }
}
