//! Spool against a recipient domain without IDMX. `legacy.invalid` can never
//! resolve (RFC 6761), so every attempt ends in the SMTP hand-off, here a fake
//! sendmail. The IDMX retry paths need DNS and live in the devnet (flow 2).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use hickory_resolver::TokioResolver;
use idmx_client::identity::Identity;
use idmx_client::pin::PinStore;
use idmx_client::queue::{Disposition, Event, Mta, Spool};
use idmx_client::schedule::RetryPolicy;
use idmx_client::sender::{Sender, http_client_builder};
use idmx_core::envelope::{Envelope, ReversePath};

fn fake_sendmail(dir: &Path, exit_code: u8) -> PathBuf {
    let path = dir.join("sendmail");
    let script = format!("#!/bin/sh\ncat >\"$0.input\"\nexit {exit_code}\n");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Queues one message and runs the spool once.
async fn queue_and_run(dir: &Path, sendmail_exit_code: u8) -> (Spool, Vec<Event>) {
    let sendmail = fake_sendmail(dir, sendmail_exit_code);
    let spool = Spool::open(&dir.join("spool")).unwrap();
    let envelope = Envelope::new(
        ReversePath::Mailbox("alice@sender.example".parse().unwrap()),
        vec!["bob@legacy.invalid".parse().unwrap()],
    )
    .unwrap();
    spool.add(&envelope, b"Subject: Hello\r\n\r\n").unwrap();

    let sender = Sender::new(
        http_client_builder().build().unwrap(),
        TokioResolver::builder_tokio().unwrap().build().unwrap(),
        Identity::new(
            SigningKey::from_bytes(&[7; 32]),
            "s1._idmxkey.sender.example".parse().unwrap(),
        ),
    );
    let mut pins = PinStore::open(&spool.pins_path()).unwrap();
    let mut mta = Mta {
        sender: &sender,
        pins: &mut pins,
        policy: &RetryPolicy::default(),
        sendmail: &sendmail,
    };
    let events = spool.run_due(&mut mta, SystemTime::now()).await.unwrap();
    (spool, events)
}

#[tokio::test]
async fn run_due_should_hand_message_to_sendmail_when_domain_has_no_idmx() {
    let dir = tempfile::tempdir().unwrap();

    queue_and_run(dir.path(), 0).await;

    assert_eq!(
        std::fs::read(dir.path().join("sendmail.input")).unwrap(),
        b"Subject: Hello\r\n\r\n"
    );
}

#[tokio::test]
async fn run_due_should_remove_the_job_after_hand_off() {
    let dir = tempfile::tempdir().unwrap();

    let (spool, events) = queue_and_run(dir.path(), 0).await;

    assert!(matches!(events[0].disposition, Disposition::HandedToSmtp));
    assert_eq!(spool.pending().unwrap(), 0);
}

#[tokio::test]
async fn run_due_should_keep_the_job_when_sendmail_fails() {
    let dir = tempfile::tempdir().unwrap();

    let (spool, events) = queue_and_run(dir.path(), 75).await;

    assert!(matches!(
        events[0].disposition,
        Disposition::HandOffFailed(_)
    ));
    assert_eq!(spool.pending().unwrap(), 1);
}
