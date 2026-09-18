//! `idmx`: command-line sender for IDMX.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hickory_resolver::TokioResolver;
use idmx_client::identity::Identity;
use idmx_client::pin::PinStore;
use idmx_client::queue::{Disposition, Event, Mta, Spool, random_key};
use idmx_client::schedule::RetryPolicy;
use idmx_client::sender::{Attempt, Sender, SmtpReason, http_client_builder};
use idmx_core::discovery::{Discovery, discover, lookup_key};
use idmx_core::domain::Domain;
use idmx_core::envelope::{Envelope, ReversePath};
use idmx_core::idempotency::IdempotencyKey;
use idmx_core::key::{KeyId, KeyRecord};
use idmx_core::mailbox::Mailbox;
use idmx_core::result::Outcome;
use reqwest::Certificate;

#[derive(Parser)]
#[command(version, about = "IDMX sender and DNS inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Show the IDMX endpoints a domain advertises on _idmx.<domain>")]
    Discover { domain: Domain },
    #[command(about = "Show the key record published at <selector>._idmxkey.<domain>")]
    Key { keyid: KeyId },
    #[command(about = "Print the TXT record value to publish for a private key")]
    KeyRecord {
        #[arg(help = "PKCS#8 PEM Ed25519 key (openssl genpkey -algorithm ed25519)")]
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        keyid: KeyId,
    },
    #[command(about = "Deliver one RFC 5322 message over IDMX")]
    Send(SendArgs),
    #[command(subcommand, about = "Spool with retries and SMTP fallback")]
    Queue(QueueCommand),
}

#[derive(Subcommand)]
enum QueueCommand {
    #[command(about = "Queue one RFC 5322 message for one recipient domain")]
    Add {
        #[arg(long)]
        spool: PathBuf,
        #[arg(help = "Envelope sender; omit for the null reverse-path (DSNs)")]
        #[arg(long)]
        from: Option<Mailbox>,
        #[arg(help = "Recipients, all in one domain")]
        #[arg(long, required = true, num_args = 1..)]
        to: Vec<Mailbox>,
        #[arg(help = "Message file; standard input if omitted")]
        #[arg(long)]
        message: Option<PathBuf>,
    },
    #[command(about = "Make one attempt for every due job (run it from a timer)")]
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    #[arg(long)]
    spool: PathBuf,
    #[arg(help = "PKCS#8 PEM Ed25519 private key of the sending domain")]
    #[arg(long)]
    key: PathBuf,
    #[arg(help = "Name the public key is published under: <selector>._idmxkey.<domain>")]
    #[arg(long)]
    keyid: KeyId,
    #[arg(help = "Additional trusted root certificate (PEM), e.g. a devnet CA")]
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(help = "Sendmail-compatible command for the SMTP hand-off")]
    #[arg(long, default_value = "/usr/sbin/sendmail")]
    sendmail: PathBuf,
    #[arg(help = "Seconds before the first retry (testing; the specification says 60)")]
    #[arg(long)]
    first_delay: Option<u64>,
    #[arg(help = "Seconds of the SMTP fallback window (testing; the specification says 7200)")]
    #[arg(long)]
    fallback_window: Option<u64>,
}

#[derive(clap::Args)]
struct SendArgs {
    #[arg(help = "PKCS#8 PEM Ed25519 private key of the sending domain")]
    #[arg(long)]
    key: PathBuf,
    #[arg(help = "Name the public key is published under: <selector>._idmxkey.<domain>")]
    #[arg(long)]
    keyid: KeyId,
    #[arg(help = "Envelope sender; omit for the null reverse-path (DSNs)")]
    #[arg(long)]
    from: Option<Mailbox>,
    #[arg(help = "Recipients, all in one domain")]
    #[arg(long, required = true, num_args = 1..)]
    to: Vec<Mailbox>,
    #[arg(help = "Message file; standard input if omitted")]
    #[arg(long)]
    message: Option<PathBuf>,
    #[arg(help = "Reuse the key of an earlier attempt when retrying; random if omitted")]
    #[arg(long)]
    idempotency_key: Option<IdempotencyKey>,
    #[arg(help = "Additional trusted root certificate (PEM), e.g. a devnet CA")]
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(help = "Skip discovery and deliver to this host[:port] (debugging)")]
    #[arg(long)]
    endpoint: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let resolver = TokioResolver::builder_tokio()
        .context("reading system DNS configuration")?
        .build()
        .context("building DNS resolver")?;

    match cli.command {
        Command::Discover { domain } => print_discovery(&resolver, &domain).await,
        Command::Key { keyid } => print_key(&resolver, &keyid).await,
        Command::KeyRecord { key, keyid } => {
            let identity = load_identity(&key, keyid)?;
            println!("{}. TXT \"{}\"", identity.keyid(), identity.key_record());
            Ok(())
        }
        Command::Send(args) => send(resolver, args).await,
        Command::Queue(QueueCommand::Add {
            spool,
            from,
            to,
            message,
        }) => {
            let envelope =
                Envelope::new(ReversePath::from(from), to).context("building envelope")?;
            let id = Spool::open(&spool)?.add(&envelope, &read_message(message.as_deref())?)?;
            println!("queued as {id}");
            Ok(())
        }
        Command::Queue(QueueCommand::Run(args)) => run_queue(resolver, args).await,
    }
}

async fn print_discovery(resolver: &TokioResolver, domain: &Domain) -> Result<()> {
    let discovery = discover(resolver, domain)
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

async fn print_key(resolver: &TokioResolver, keyid: &KeyId) -> Result<()> {
    let record = lookup_key(resolver, keyid)
        .await
        .with_context(|| format!("looking up key {keyid}"))?;

    match record {
        KeyRecord::Active(key) => println!("{}", KeyRecord::render(&key)),
        KeyRecord::Revoked => println!("{keyid} is revoked"),
    }
    Ok(())
}

async fn send(resolver: TokioResolver, args: SendArgs) -> Result<()> {
    let identity = load_identity(&args.key, args.keyid)?;
    let envelope =
        Envelope::new(ReversePath::from(args.from), args.to).context("building envelope")?;
    let message = read_message(args.message.as_deref())?;
    let idempotency_key = match args.idempotency_key {
        Some(key) => key,
        None => random_key()?,
    };
    let sender = Sender::new(http_client(args.ca.as_deref())?, resolver, identity);

    eprintln!("idempotency key: {idempotency_key}");
    let attempt = if let Some(authority) = &args.endpoint {
        let origin = format!("https://{authority}");
        sender
            .deliver_via(&origin, authority, &envelope, &message, &idempotency_key)
            .await
    } else {
        let mut pins = PinStore::in_memory();
        sender
            .send(&envelope, &message, &idempotency_key, &mut pins)
            .await
    }
    .context("preparing delivery")?;
    report(attempt)
}

async fn run_queue(resolver: TokioResolver, args: RunArgs) -> Result<()> {
    let identity = load_identity(&args.key, args.keyid)?;
    let sender = Sender::new(http_client(args.ca.as_deref())?, resolver, identity);
    let spool = Spool::open(&args.spool)?;
    let mut pins = PinStore::open(&spool.pins_path())?;
    let mut policy = RetryPolicy::default();
    if let Some(seconds) = args.first_delay {
        policy.first_delay = Duration::from_secs(seconds);
    }
    if let Some(seconds) = args.fallback_window {
        policy.fallback_window = Duration::from_secs(seconds);
    }

    let mut mta = Mta {
        sender: &sender,
        pins: &mut pins,
        policy: &policy,
        sendmail: &args.sendmail,
    };
    let now = SystemTime::now();
    for event in spool.run_due(&mut mta, now).await? {
        print_event(&event, now);
    }
    println!("{} job(s) still queued", spool.pending()?);
    Ok(())
}

fn print_event(event: &Event, now: SystemTime) {
    let status = match &event.disposition {
        Disposition::Accepted => "accepted over IDMX".to_owned(),
        Disposition::HandedToSmtp => "handed to SMTP".to_owned(),
        Disposition::RetryAt(time) => format!(
            "retry in {} s",
            time.duration_since(now).unwrap_or_default().as_secs()
        ),
        Disposition::HandOffFailed(error) => format!("SMTP hand-off failed, still queued: {error}"),
        Disposition::Failed(reason) => format!("failed: {reason}"),
    };
    for recipient in &event.recipients {
        println!("{} {recipient}: {status}", event.job);
    }
}

/// Prints the outcome; fails unless every recipient was accepted.
fn report(attempt: Attempt) -> Result<()> {
    match attempt {
        Attempt::Completed(result) => {
            let mut all_accepted = true;
            for recipient in &result.results {
                let status = match &recipient.outcome {
                    Outcome::Accepted => "accepted".to_owned(),
                    Outcome::Rejected { problem } => format!("rejected ({})", problem.problem_type),
                    Outcome::Deferred { problem, .. } => {
                        format!("deferred ({})", problem.problem_type)
                    }
                };
                all_accepted &= matches!(recipient.outcome, Outcome::Accepted);
                println!("{}: {status}", recipient.recipient);
            }
            if !all_accepted {
                bail!("not every recipient was accepted");
            }
            Ok(())
        }
        Attempt::Rejected(problem) => bail!(
            "rejected permanently: {} {}",
            problem.problem_type,
            problem.detail.unwrap_or_default()
        ),
        Attempt::TryLater { problem, .. } => bail!(
            "temporary failure, retry with the same idempotency key{}",
            problem.map_or_else(String::new, |problem| format!(": {}", problem.problem_type))
        ),
        Attempt::Unreachable(error) => {
            Err(error).context("endpoint unreachable; retry with the same idempotency key")
        }
        Attempt::UseSmtp(SmtpReason::NotAdvertised) => {
            bail!("recipient domain does not advertise IDMX; use SMTP")
        }
        Attempt::UseSmtp(SmtpReason::NoCommonVersion) => bail!("no common IDMX version; use SMTP"),
        Attempt::UseSmtp(SmtpReason::DiscoveryFailed(error)) => {
            Err(error).context("IDMX discovery failed; without a pin, use SMTP")
        }
    }
}

fn load_identity(key: &Path, keyid: KeyId) -> Result<Identity> {
    Identity::from_pem_file(key, keyid)
        .with_context(|| format!("loading private key {}", key.display()))
}

fn read_message(path: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(path) = path {
        return std::fs::read(path).with_context(|| format!("reading message {}", path.display()));
    }
    let mut message = Vec::new();
    std::io::stdin()
        .read_to_end(&mut message)
        .context("reading message from standard input")?;
    Ok(message)
}

/// HTTPS only, system roots plus `ca`.
fn http_client(ca: Option<&Path>) -> Result<reqwest::Client> {
    let mut builder = http_client_builder().https_only(true);
    if let Some(ca) = ca {
        let pem = std::fs::read(ca)
            .with_context(|| format!("reading CA certificate {}", ca.display()))?;
        let certificate = Certificate::from_pem(&pem)
            .with_context(|| format!("parsing CA certificate {}", ca.display()))?;
        builder = builder.tls_certs_merge([certificate]);
    }
    builder.build().context("building HTTPS client")
}
