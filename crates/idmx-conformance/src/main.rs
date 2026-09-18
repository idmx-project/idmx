//! `idmx-conformance`: check an IDMX receiver against the spec.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use idmx_conformance::{Origin, http_client_builder, run};
use reqwest::Certificate;

#[derive(Parser)]
#[command(version, about = "Check an IDMX receiver against the spec")]
struct Cli {
    #[arg(help = "Origin of the receiver, e.g. https://idmx.example.org:8443")]
    origin: Origin,
    #[arg(help = "Additional PEM root certificate to trust (test networks)")]
    #[arg(long)]
    ca: Option<PathBuf>,
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

    let report = run(&http, &cli.origin).await;
    println!("{report}");
    Ok(if report.conforms() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
