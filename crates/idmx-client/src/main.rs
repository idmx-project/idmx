//! `idmx`: command-line sender for IDMX.
//!
//! So far it only inspects what a domain publishes in DNS:
//!
//! ```text
//! idmx discover <domain>    SVCB endpoints on _idmx.<domain>
//! idmx key <keyid>          key record at <selector>._idmxkey.<domain>
//! ```

use anyhow::{Context, Result, bail};
use hickory_resolver::TokioResolver;
use idmx_core::discovery::{Discovery, discover, lookup_key};
use idmx_core::domain::Domain;
use idmx_core::key::{KeyId, KeyRecord};

const USAGE: &str = "usage: idmx discover <domain> | idmx key <keyid>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [command, target] = args.as_slice() else {
        bail!(USAGE);
    };
    let resolver = TokioResolver::builder_tokio()
        .context("reading system DNS configuration")?
        .build()
        .context("building DNS resolver")?;

    match command.as_str() {
        "discover" => print_discovery(&resolver, target).await,
        "key" => print_key(&resolver, target).await,
        _ => bail!(USAGE),
    }
}

async fn print_discovery(resolver: &TokioResolver, domain: &str) -> Result<()> {
    let domain: Domain = domain
        .parse()
        .with_context(|| format!("parsing domain `{domain}`"))?;
    let discovery = discover(resolver, &domain)
        .await
        .with_context(|| format!("discovering IDMX support of {domain}"))?;

    match discovery {
        Discovery::Supported(endpoints) => {
            for endpoint in endpoints {
                let protocols = if endpoint.supports_http3() {
                    "h2,h3"
                } else {
                    "h2"
                };
                println!("https://{} ({protocols})", endpoint.authority());
            }
        }
        Discovery::Unsupported => println!("{domain} does not advertise IDMX; use SMTP"),
    }
    Ok(())
}

async fn print_key(resolver: &TokioResolver, keyid: &str) -> Result<()> {
    let keyid: KeyId = keyid
        .parse()
        .with_context(|| format!("parsing keyid `{keyid}`"))?;
    let record = lookup_key(resolver, &keyid)
        .await
        .with_context(|| format!("looking up key {keyid}"))?;

    match record {
        KeyRecord::Active(key) => println!("{}", KeyRecord::render(&key)),
        KeyRecord::Revoked => println!("{keyid} is revoked"),
    }
    Ok(())
}
