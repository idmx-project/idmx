//! `idmxd`: IDMX receiver daemon, a front door beside the MTA.

use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use idmx_server::app::{App, router};
use idmx_server::config::{Config, Transport};
use idmx_server::idempotency::IdempotencyStore;
use idmx_server::keys::DnsKeySource;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::signal::unix::{SignalKind, signal};

/// How long requests in flight may take after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let [config_path] = args.as_slice() else {
        bail!("usage: idmxd <config.toml>");
    };
    let config = load_config(Path::new(config_path))?;

    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data directory {}", config.data_dir.display()))?;
    let idempotency = IdempotencyStore::open(&config.idempotency_log(), SystemTime::now())
        .with_context(|| format!("opening {}", config.idempotency_log().display()))?;
    let keys = DnsKeySource::from_system_conf().context("reading system DNS configuration")?;

    let listen = config.listen;
    let transport = config.transport.clone();
    tracing::info!(%listen, domain = %config.domain, authority = %config.authority, "starting idmxd");
    let service = router(App {
        config,
        keys: Box::new(keys),
        idempotency,
    })
    .into_make_service();

    let handle = axum_server::Handle::new();
    tokio::spawn(shut_down_on_signal(handle.clone()));

    match transport {
        Transport::Tls { cert, key } => {
            let tls = RustlsConfig::from_config(tls_config(&cert, &key)?.into());
            axum_server::bind_rustls(listen, tls)
                .handle(handle)
                .serve(service)
                .await
        }
        Transport::BehindProxy => {
            axum_server::bind(listen)
                .handle(handle)
                .serve(service)
                .await
        }
    }
    .with_context(|| format!("serving on {listen}"))
}

/// SIGTERM (container stop) and SIGINT: finish requests in flight, then exit.
async fn shut_down_on_signal(handle: axum_server::Handle<std::net::SocketAddr>) {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(error) => {
            tracing::warn!(%error, "cannot listen for SIGTERM");
            return;
        }
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("shutting down");
    handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
}

fn load_config(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    Config::parse(&text).with_context(|| format!("parsing config {}", path.display()))
}

/// TLS 1.3 only, HTTP/2 only (`spec/discovery.md` §4).
fn tls_config(cert: &Path, key: &Path) -> Result<ServerConfig> {
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("reading certificate chain {}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("reading private key {}", key.display()))?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("loading certificate and key")?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}
