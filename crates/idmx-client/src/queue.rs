//! A spool directory and the loop that works it off: IDMX first, retries per
//! `spec/errors.md` §3.1, SMTP hand-off when the specification allows it.
//!
//! ```text
//! <spool>/queue/<id>.json   job state        <spool>/pins.json   discovery pins
//! <spool>/queue/<id>.eml    the message      <spool>/failed/     given-up jobs
//! ```
//!
//! Generating the RFC 3464 DSN for a failed job is left to the operator's
//! MTA tooling; failed jobs are kept in `failed/` with the reason.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use idmx_core::envelope::{Envelope, EnvelopeError};
use idmx_core::idempotency::{IdempotencyKey, IdempotencyKeyError};
use idmx_core::mailbox::Mailbox;
use idmx_core::result::{DeliveryResult, Outcome};
use serde::{Deserialize, Serialize};

use crate::pin::PinStore;
use crate::schedule::{History, RetryPolicy, SmtpFallback, Step};
use crate::sender::{Attempt, SendError, Sender};
use crate::smtp::hand_off;

/// Why the spool could not be worked on. Delivery failures are not errors;
/// they are [`Event`]s.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// A spool file cannot be read, written, or moved.
    #[error("spool file {}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// A job file is not what this module wrote.
    #[error("job file {}: {source}", path.display())]
    Parse {
        /// The job file.
        path: PathBuf,
        /// The underlying failure.
        source: serde_json::Error,
    },
    /// The system has no randomness for an idempotency key.
    #[error("reading system randomness: {0}")]
    Random(#[from] getrandom::Error),
    /// A generated or stored idempotency key is invalid.
    #[error(transparent)]
    Key(#[from] IdempotencyKeyError),
    /// The envelope for the deferred recipients cannot be built.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    /// The delivery request cannot be built.
    #[error(transparent)]
    Send(#[from] SendError),
}

/// How far a job has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Progress {
    /// No attempt yet.
    New,
    /// At least one attempt ended in a temporary failure.
    Tried {
        /// Seconds since the Unix epoch.
        first_attempt: u64,
        attempts: u32,
        fallback: SmtpFallback,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Job {
    envelope: Envelope,
    idempotency_key: String,
    progress: Progress,
    /// Seconds since the Unix epoch.
    next_attempt: u64,
}

/// What happened to some recipients of a job during [`Spool::run_due`].
#[derive(Debug)]
pub struct Event {
    /// The job.
    pub job: String,
    /// The recipients this event is about.
    pub recipients: Vec<Mailbox>,
    /// What happened.
    pub disposition: Disposition,
}

/// The fate of a group of recipients.
#[derive(Debug)]
pub enum Disposition {
    /// Delivered over IDMX.
    Accepted,
    /// Handed to the local MTA for SMTP delivery.
    HandedToSmtp,
    /// Still queued; next IDMX attempt not before this time.
    RetryAt(SystemTime),
    /// SMTP was due but the MTA did not take the message; still queued.
    HandOffFailed(String),
    /// Given up (permanent rejection or give-up time); moved to `failed/`.
    Failed(String),
}

/// Everything [`Spool::run_due`] needs besides the spool itself.
pub struct Mta<'a> {
    /// Performs the IDMX attempts.
    pub sender: &'a Sender,
    /// Discovery pins, usually [`Spool::pins_path`].
    pub pins: &'a mut PinStore,
    /// The retry schedule.
    pub policy: &'a RetryPolicy,
    /// The sendmail-compatible command for the SMTP hand-off.
    pub sendmail: &'a Path,
}

/// A spool directory.
#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    /// Opens `dir`, creating it if needed.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Io`] if the directories cannot be created.
    pub fn open(dir: &Path) -> Result<Self, QueueError> {
        let spool = Self {
            dir: dir.to_owned(),
        };
        for path in [spool.queue_dir(), spool.failed_dir()] {
            std::fs::create_dir_all(&path).map_err(io_error(&path))?;
        }
        Ok(spool)
    }

    /// Where the pins of this spool live.
    #[must_use]
    pub fn pins_path(&self) -> PathBuf {
        self.dir.join("pins.json")
    }

    fn queue_dir(&self) -> PathBuf {
        self.dir.join("queue")
    }

    fn failed_dir(&self) -> PathBuf {
        self.dir.join("failed")
    }

    fn job_path(&self, id: &str) -> PathBuf {
        self.queue_dir().join(format!("{id}.json"))
    }

    fn message_path(&self, id: &str) -> PathBuf {
        self.queue_dir().join(format!("{id}.eml"))
    }

    /// Queues one message for one recipient domain, due immediately.
    /// Returns the job id.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] if the job cannot be written.
    pub fn add(&self, envelope: &Envelope, message: &[u8]) -> Result<String, QueueError> {
        let id = random_key()?.to_string();
        let message_path = self.message_path(&id);
        std::fs::write(&message_path, message).map_err(io_error(&message_path))?;
        self.write_job(
            &id,
            &Job {
                envelope: envelope.clone(),
                idempotency_key: random_key()?.to_string(),
                progress: Progress::New,
                next_attempt: 0,
            },
        )?;
        Ok(id)
    }

    /// Number of jobs still queued.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Io`] if the queue directory cannot be read.
    pub fn pending(&self) -> Result<usize, QueueError> {
        Ok(self.job_ids()?.len())
    }

    /// Makes one attempt for every job that is due at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError`] if the spool itself fails; delivery outcomes are
    /// reported as [`Event`]s.
    pub async fn run_due(
        &self,
        mta: &mut Mta<'_>,
        now: SystemTime,
    ) -> Result<Vec<Event>, QueueError> {
        let mut events = Vec::new();
        for id in self.job_ids()? {
            let job = self.read_job(&id)?;
            if job.next_attempt <= unix_seconds(now) {
                self.run_job(&id, job, mta, now, &mut events).await?;
            }
        }
        Ok(events)
    }

    async fn run_job(
        &self,
        id: &str,
        job: Job,
        mta: &mut Mta<'_>,
        now: SystemTime,
        events: &mut Vec<Event>,
    ) -> Result<(), QueueError> {
        let message_path = self.message_path(id);
        let message = std::fs::read(&message_path).map_err(io_error(&message_path))?;
        let key: IdempotencyKey = job.idempotency_key.parse()?;
        let attempt = mta
            .sender
            .send(&job.envelope, &message, &key, mta.pins)
            .await?;

        let mut event = |recipients: &[Mailbox], disposition| {
            events.push(Event {
                job: id.to_owned(),
                recipients: recipients.to_vec(),
                disposition,
            });
        };
        let all = job.envelope.to();

        let failure = match attempt {
            Attempt::Completed(result) => {
                let sorted = sort_results(all, result);
                if !sorted.accepted.is_empty() {
                    event(&sorted.accepted, Disposition::Accepted);
                }
                for (recipient, reason) in sorted.rejected {
                    self.record_failure(id, &job, std::slice::from_ref(&recipient), &reason)?;
                    event(&[recipient], Disposition::Failed(reason));
                }
                if sorted.deferred.is_empty() {
                    return self.remove(id);
                }
                // `spec/delivery.md` §5.3: a new delivery for the rest.
                Failure {
                    job: Job {
                        envelope: Envelope::new(job.envelope.from().clone(), sorted.deferred)?,
                        idempotency_key: random_key()?.to_string(),
                        ..job
                    },
                    fallback: SmtpFallback::Never,
                    retry_after: sorted.retry_after,
                }
            }
            Attempt::Rejected(problem) => {
                let reason = problem.problem_type.to_string();
                self.record_failure(id, &job, all, &reason)?;
                event(all, Disposition::Failed(reason));
                return self.remove(id);
            }
            Attempt::UseSmtp(_) => {
                return self.smtp(id, job, &message, mta, now, &mut event);
            }
            Attempt::TryLater {
                fallback,
                retry_after,
                ..
            } => Failure {
                job,
                fallback,
                retry_after,
            },
            Attempt::Unreachable(_) => Failure {
                job,
                fallback: SmtpFallback::AfterWindow,
                retry_after: None,
            },
        };
        self.after_failure(id, failure, &message, mta, now, &mut event)
    }

    fn after_failure(
        &self,
        id: &str,
        failure: Failure,
        message: &[u8],
        mta: &Mta<'_>,
        now: SystemTime,
        event: &mut impl FnMut(&[Mailbox], Disposition),
    ) -> Result<(), QueueError> {
        let Failure {
            mut job,
            fallback,
            retry_after,
        } = failure;
        let history = match job.progress {
            Progress::New => History {
                first_attempt: now,
                attempts: 1,
                fallback,
            },
            Progress::Tried {
                first_attempt,
                attempts,
                fallback: earlier,
            } => History {
                first_attempt: SystemTime::UNIX_EPOCH + Duration::from_secs(first_attempt),
                attempts: attempts.saturating_add(1),
                // One answer from the receiver rules SMTP out for good.
                fallback: match (earlier, fallback) {
                    (SmtpFallback::AfterWindow, SmtpFallback::AfterWindow) => {
                        SmtpFallback::AfterWindow
                    }
                    (SmtpFallback::Never, _) | (_, SmtpFallback::Never) => SmtpFallback::Never,
                },
            },
        };
        job.progress = Progress::Tried {
            first_attempt: unix_seconds(history.first_attempt),
            attempts: history.attempts,
            fallback: history.fallback,
        };

        match mta
            .policy
            .after_failure(&history, now, retry_after, jitter()?)
        {
            Step::RetryAt(time) => {
                job.next_attempt = unix_seconds(time);
                self.write_job(id, &job)?;
                event(job.envelope.to(), Disposition::RetryAt(time));
                Ok(())
            }
            Step::UseSmtp => self.smtp(id, job, message, mta, now, event),
            Step::GiveUp => {
                let reason = "gave up after the retry period".to_owned();
                self.record_failure(id, &job, job.envelope.to(), &reason)?;
                event(job.envelope.to(), Disposition::Failed(reason));
                self.remove(id)
            }
        }
    }

    fn smtp(
        &self,
        id: &str,
        mut job: Job,
        message: &[u8],
        mta: &Mta<'_>,
        now: SystemTime,
        event: &mut impl FnMut(&[Mailbox], Disposition),
    ) -> Result<(), QueueError> {
        match hand_off(mta.sendmail, &job.envelope, message) {
            Ok(()) => {
                event(job.envelope.to(), Disposition::HandedToSmtp);
                self.remove(id)
            }
            Err(error) => {
                job.next_attempt = unix_seconds(now + mta.policy.first_delay);
                self.write_job(id, &job)?;
                event(
                    job.envelope.to(),
                    Disposition::HandOffFailed(error.to_string()),
                );
                Ok(())
            }
        }
    }

    fn job_ids(&self) -> Result<Vec<String>, QueueError> {
        let dir = self.queue_dir();
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(io_error(&dir))? {
            let path = entry.map_err(io_error(&dir))?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
                && let Some(id) = path.file_stem().and_then(|stem| stem.to_str())
            {
                ids.push(id.to_owned());
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn read_job(&self, id: &str) -> Result<Job, QueueError> {
        let path = self.job_path(id);
        let bytes = std::fs::read(&path).map_err(io_error(&path))?;
        serde_json::from_slice(&bytes).map_err(|source| QueueError::Parse { path, source })
    }

    /// Atomic, so that a crash never leaves half a job.
    fn write_job(&self, id: &str, job: &Job) -> Result<(), QueueError> {
        let path = self.job_path(id);
        let json = serde_json::to_vec_pretty(job).map_err(|source| QueueError::Parse {
            path: path.clone(),
            source,
        })?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, json)
            .and_then(|()| std::fs::rename(&temporary, &path))
            .map_err(io_error(&path))
    }

    fn remove(&self, id: &str) -> Result<(), QueueError> {
        for path in [self.job_path(id), self.message_path(id)] {
            std::fs::remove_file(&path).map_err(io_error(&path))?;
        }
        Ok(())
    }

    /// Keeps what a bounce needs: who, why, and the message.
    fn record_failure(
        &self,
        id: &str,
        job: &Job,
        recipients: &[Mailbox],
        reason: &str,
    ) -> Result<(), QueueError> {
        let record = serde_json::json!({
            "from": job.envelope.from(),
            "recipients": recipients,
            "reason": reason,
        });
        let path = self
            .failed_dir()
            .join(format!("{id}.{}.json", job.idempotency_key));
        std::fs::write(&path, record.to_string()).map_err(io_error(&path))?;

        let message = self.failed_dir().join(format!("{id}.eml"));
        std::fs::copy(self.message_path(id), &message)
            .map(drop)
            .map_err(io_error(&message))
    }
}

/// A temporary failure of `job` (already narrowed to the recipients that
/// are still open).
struct Failure {
    job: Job,
    fallback: SmtpFallback,
    retry_after: Option<Duration>,
}

struct Sorted {
    accepted: Vec<Mailbox>,
    rejected: Vec<(Mailbox, String)>,
    deferred: Vec<Mailbox>,
    /// The longest `retry_after` among the deferred recipients.
    retry_after: Option<Duration>,
}

/// Sorts the envelope recipients by outcome. A recipient the receiver did not
/// report on is treated as deferred.
fn sort_results(recipients: &[Mailbox], result: DeliveryResult) -> Sorted {
    let mut sorted = Sorted {
        accepted: Vec::new(),
        rejected: Vec::new(),
        deferred: Vec::new(),
        retry_after: None,
    };
    let mut results = result.results;
    for recipient in recipients {
        let outcome = results
            .iter()
            .position(|result| &result.recipient == recipient)
            .map(|index| results.swap_remove(index).outcome);
        match outcome {
            Some(Outcome::Accepted) => sorted.accepted.push(recipient.clone()),
            Some(Outcome::Rejected { problem }) => sorted
                .rejected
                .push((recipient.clone(), problem.problem_type.to_string())),
            Some(Outcome::Deferred { retry_after, .. }) => {
                sorted.deferred.push(recipient.clone());
                sorted.retry_after = sorted.retry_after.max(retry_after);
            }
            None => sorted.deferred.push(recipient.clone()),
        }
    }
    sorted
}

/// A fresh idempotency key: 128 random bits, hex encoded.
///
/// # Errors
///
/// Returns [`QueueError::Random`] if the system has no randomness.
pub fn random_key() -> Result<IdempotencyKey, QueueError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(format!("{:032x}", u128::from_le_bytes(bytes)).parse()?)
}

/// A random number in `-1.0..=1.0`.
fn jitter() -> Result<f64, QueueError> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes)?;
    Ok(f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX) * 2.0 - 1.0)
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> QueueError {
    let path = path.to_owned();
    move |source| QueueError::Io { path, source }
}

#[cfg(test)]
mod tests {
    use idmx_core::problem::{Problem, ProblemKind};
    use idmx_core::result::RecipientResult;

    use super::*;

    fn mailbox(local: &str) -> Mailbox {
        format!("{local}@receiver.example").parse().unwrap()
    }

    fn result(local: &str, outcome: Outcome) -> RecipientResult {
        RecipientResult {
            recipient: mailbox(local),
            outcome,
        }
    }

    fn deferred(retry_after: Option<u64>) -> Outcome {
        Outcome::Deferred {
            problem: Problem::new(ProblemKind::MailboxFull),
            retry_after: retry_after.map(Duration::from_secs),
        }
    }

    #[test]
    fn sort_results_should_group_recipients_by_outcome() {
        let rejected = Outcome::Rejected {
            problem: Problem::new(ProblemKind::RecipientNotFound),
        };
        let sorted = sort_results(
            &[mailbox("a"), mailbox("b"), mailbox("c")],
            DeliveryResult {
                results: vec![
                    result("a", Outcome::Accepted),
                    result("b", rejected),
                    result("c", deferred(None)),
                ],
            },
        );

        assert_eq!(
            (sorted.accepted, sorted.rejected.len(), sorted.deferred),
            (vec![mailbox("a")], 1, vec![mailbox("c")])
        );
    }

    #[test]
    fn sort_results_should_keep_the_longest_retry_after() {
        let sorted = sort_results(
            &[mailbox("a"), mailbox("b")],
            DeliveryResult {
                results: vec![
                    result("a", deferred(Some(30))),
                    result("b", deferred(Some(600))),
                ],
            },
        );

        assert_eq!(sorted.retry_after, Some(Duration::from_secs(600)));
    }

    #[test]
    fn sort_results_should_defer_recipients_the_receiver_left_out() {
        let sorted = sort_results(&[mailbox("a")], DeliveryResult { results: vec![] });

        assert_eq!(sorted.deferred, vec![mailbox("a")]);
    }

    #[test]
    fn random_key_should_differ_between_calls() {
        assert_ne!(random_key().unwrap(), random_key().unwrap());
    }
}
