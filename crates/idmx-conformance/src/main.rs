//! `idmx-conformance`: check an IDMX receiver against the spec.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use idmx_conformance::delivery::DeliveryProbe;
use idmx_conformance::{Origin, http_client_builder, run};
use idmx_core::key::KeyId;
use idmx_core::mailbox::Mailbox;
use reqwest::Certificate;

#[derive(Parser)]
#[command(version, about = "Check an IDMX receiver against the spec")]
struct Cli {
    #[arg(help = "Origin of the receiver, e.g. https://idmx.example.org:8443")]
    origin: Origin,
    #[arg(help = "Additional PEM root certificate to trust (test networks)")]
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(help = "PKCS#8 PEM Ed25519 key for the signed checks")]
    #[arg(long, requires_all = ["keyid", "recipient"])]
    key: Option<PathBuf>,
    #[arg(help = "Name the public key is published under: <selector>._idmxkey.<domain>")]
    #[arg(long, requires = "key")]
    keyid: Option<KeyId>,
    #[arg(help = "Existing mailbox at the receiver; probe messages are delivered to it")]
    #[arg(long, requires = "key")]
    recipient: Option<Mailbox>,
}

fn load_probe(cli: &Cli) -> Result<Option<DeliveryProbe>> {
    let (Some(path), Some(keyid), Some(recipient)) = (&cli.key, &cli.keyid, &cli.recipient) else {
        return Ok(None);
    };
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = SigningKey::from_pkcs8_pem(&pem)
        .map_err(|_| anyhow::anyhow!("{} is not a PKCS#8 PEM Ed25519 key", path.display()))?;
    Ok(Some(DeliveryProbe::new(
        key,
        keyid.clone(),
        recipient.clone(),
    )))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    let mut builder = http_client_builder();
    if cli.origin.is_plain_http() {
        builder = builder.http2_prior_knowledge();
    }
    if let Some(path) = &cli.ca {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        builder = builder.add_root_certificate(Certificate::from_pem(&pem).context("parsing CA")?);
    }
    let http = builder.build().context("building the HTTP client")?;

    let probe = load_probe(&cli)?;
    if probe.is_none() {
        eprintln!("signed checks not run: pass --key, --keyid, and --recipient");
    }

    let report = run(&http, &cli.origin, probe.as_ref()).await;
    println!("{report}");
    Ok(if report.conforms() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
