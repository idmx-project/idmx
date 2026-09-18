//! Idempotency store (`spec/delivery.md` §4): remembers the response of every
//! completed delivery for at least seven days, scoped per signing domain.
//!
//! State lives in memory and is mirrored to an append-only JSON-lines log, so
//! a restart does not forget deliveries.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use idmx_core::domain::Domain;
use idmx_core::idempotency::IdempotencyKey;
use serde::{Deserialize, Serialize};

/// Minimum retention the spec mandates.
pub const RETENTION: Duration = Duration::from_hours(7 * 24);

type Scope = (Domain, IdempotencyKey);

#[derive(Debug)]
enum Entry {
    /// A request with this key is being processed right now.
    InFlight,
    /// A `200` response was produced.
    Done {
        content_digest: String,
        response: String,
        first_seen: SystemTime,
    },
}

/// One line of the log file.
#[derive(Serialize, Deserialize)]
struct LogLine {
    domain: String,
    key: String,
    content_digest: String,
    response: String,
    first_seen: u64,
}

#[derive(Debug)]
struct Inner {
    entries: HashMap<Scope, Entry>,
    log: File,
}

/// What to do with a request, decided from its idempotency key.
#[derive(Debug)]
#[must_use]
pub enum Admission {
    /// First time this key is seen: process, then [`Reservation::complete`].
    Fresh(Reservation),
    /// Same key, same content: return this stored `200` body again.
    Replay(String),
    /// Same key, different content: `idempotency_conflict`.
    Conflict,
    /// Same key is being processed concurrently: `temporary_failure`.
    InFlight,
}

/// Shared handle to the store.
#[derive(Debug, Clone)]
pub struct IdempotencyStore {
    inner: Arc<Mutex<Inner>>,
}

impl IdempotencyStore {
    /// Opens (or creates) the log at `path`, loads entries younger than
    /// [`RETENTION`], and rewrites the log without the expired ones.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the log cannot be read or written.
    pub fn open(path: &Path, now: SystemTime) -> io::Result<Self> {
        let lines = match File::open(path) {
            Ok(file) => read_live_lines(file, now)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };

        let mut log = File::create(path)?;
        let mut entries = HashMap::with_capacity(lines.len());
        for (scope, line, entry) in lines {
            writeln!(log, "{line}")?;
            entries.insert(scope, entry);
        }
        log.sync_all()?;
        let log = OpenOptions::new().append(true).open(path)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { entries, log })),
        })
    }

    /// Decides how to handle a verified request.
    pub fn admit(
        &self,
        domain: &Domain,
        key: &IdempotencyKey,
        content_digest: &str,
        now: SystemTime,
    ) -> Admission {
        let scope = (domain.clone(), key.clone());
        let mut inner = self.lock();

        match inner.entries.get(&scope) {
            Some(Entry::InFlight) => return Admission::InFlight,
            Some(Entry::Done { first_seen, .. }) if is_expired(*first_seen, now) => {}
            Some(Entry::Done {
                content_digest: stored,
                response,
                ..
            }) => {
                return if stored == content_digest {
                    Admission::Replay(response.clone())
                } else {
                    Admission::Conflict
                };
            }
            None => {}
        }

        inner.entries.insert(scope.clone(), Entry::InFlight);
        Admission::Fresh(Reservation {
            store: self.clone(),
            scope: Some(scope),
            content_digest: content_digest.to_owned(),
            first_seen: now,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The map stays consistent even if a holder panicked mid-operation.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Exclusive right to process one `(domain, key)`. Dropping it without
/// [`Self::complete`] (request failed) frees the key for a retry.
#[derive(Debug)]
#[must_use = "complete the reservation, or the delivery can be repeated"]
pub struct Reservation {
    store: IdempotencyStore,
    scope: Option<Scope>,
    content_digest: String,
    first_seen: SystemTime,
}

impl Reservation {
    /// Records the `200` response body for replay.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the log cannot be written; the key is then
    /// released, because an unrecorded response must not be reported as final.
    pub fn complete(mut self, response: &str) -> io::Result<()> {
        let Some(scope) = self.scope.take() else {
            return Ok(());
        };
        let line = LogLine {
            domain: scope.0.to_string(),
            key: scope.1.to_string(),
            content_digest: self.content_digest.clone(),
            response: response.to_owned(),
            first_seen: unix_seconds(self.first_seen),
        };

        let mut inner = self.store.lock();
        let written = serde_json::to_string(&line)
            .map_err(io::Error::other)
            .and_then(|json| writeln!(inner.log, "{json}"))
            .and_then(|()| inner.log.sync_data());
        match written {
            Ok(()) => {
                inner.entries.insert(
                    scope,
                    Entry::Done {
                        content_digest: line.content_digest,
                        response: line.response,
                        first_seen: self.first_seen,
                    },
                );
                Ok(())
            }
            Err(error) => {
                inner.entries.remove(&scope);
                Err(error)
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(scope) = self.scope.take() {
            self.store.lock().entries.remove(&scope);
        }
    }
}

fn read_live_lines(file: File, now: SystemTime) -> io::Result<Vec<(Scope, String, Entry)>> {
    let mut kept = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        let Some((scope, entry)) = parse_line(&line) else {
            tracing::warn!("skipping unreadable idempotency log line");
            continue;
        };
        if let Entry::Done { first_seen, .. } = entry
            && !is_expired(first_seen, now)
        {
            kept.push((scope, line, entry));
        }
    }
    Ok(kept)
}

fn parse_line(line: &str) -> Option<(Scope, Entry)> {
    let line: LogLine = serde_json::from_str(line).ok()?;
    let scope = (line.domain.parse().ok()?, line.key.parse().ok()?);
    let entry = Entry::Done {
        content_digest: line.content_digest,
        response: line.response,
        first_seen: UNIX_EPOCH.checked_add(Duration::from_secs(line.first_seen))?,
    };
    Some((scope, entry))
}

fn is_expired(first_seen: SystemTime, now: SystemTime) -> bool {
    now.duration_since(first_seen)
        .is_ok_and(|age| age > RETENTION)
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        domain: Domain,
        key: IdempotencyKey,
        now: SystemTime,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            Self {
                path: dir.path().join("idempotency.jsonl"),
                _dir: dir,
                domain: "sender.example".parse().unwrap(),
                key: "key-1".parse().unwrap(),
                now: UNIX_EPOCH + Duration::from_secs(1_789_668_001),
            }
        }

        fn open(&self, now: SystemTime) -> IdempotencyStore {
            IdempotencyStore::open(&self.path, now).unwrap()
        }

        fn admit(&self, store: &IdempotencyStore, digest: &str, now: SystemTime) -> Admission {
            store.admit(&self.domain, &self.key, digest, now)
        }

        fn complete(&self, store: &IdempotencyStore, digest: &str, response: &str) {
            let Admission::Fresh(reservation) = self.admit(store, digest, self.now) else {
                panic!("expected a fresh admission");
            };
            reservation.complete(response).unwrap();
        }
    }

    #[test]
    fn admit_should_be_fresh_for_unknown_key() {
        let fixture = Fixture::new();

        let admission = fixture.admit(&fixture.open(fixture.now), "d1", fixture.now);

        assert!(
            matches!(admission, Admission::Fresh(_)),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn admit_should_replay_response_for_same_key_and_digest() {
        let fixture = Fixture::new();
        let store = fixture.open(fixture.now);
        fixture.complete(&store, "d1", "{\"results\":[]}");

        let admission = fixture.admit(&store, "d1", fixture.now);

        assert!(
            matches!(&admission, Admission::Replay(body) if body == "{\"results\":[]}"),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn admit_should_report_conflict_for_same_key_and_other_digest() {
        let fixture = Fixture::new();
        let store = fixture.open(fixture.now);
        fixture.complete(&store, "d1", "{}");

        let admission = fixture.admit(&store, "d2", fixture.now);

        assert!(
            matches!(admission, Admission::Conflict),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn admit_should_report_in_flight_while_reservation_is_held() {
        let fixture = Fixture::new();
        let store = fixture.open(fixture.now);
        let _held = fixture.admit(&store, "d1", fixture.now);

        let admission = fixture.admit(&store, "d1", fixture.now);

        assert!(
            matches!(admission, Admission::InFlight),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn admit_should_be_fresh_again_after_reservation_dropped() {
        let fixture = Fixture::new();
        let store = fixture.open(fixture.now);
        drop(fixture.admit(&store, "d1", fixture.now));

        let admission = fixture.admit(&store, "d1", fixture.now);

        assert!(
            matches!(admission, Admission::Fresh(_)),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn admit_should_scope_keys_per_domain() {
        let fixture = Fixture::new();
        let store = fixture.open(fixture.now);
        fixture.complete(&store, "d1", "{}");
        let other: Domain = "other.example".parse().unwrap();

        let admission = store.admit(&other, &fixture.key, "d2", fixture.now);

        assert!(
            matches!(admission, Admission::Fresh(_)),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn open_should_restore_completed_entries_from_log() {
        let fixture = Fixture::new();
        fixture.complete(&fixture.open(fixture.now), "d1", "{}");

        let admission = fixture.admit(&fixture.open(fixture.now), "d1", fixture.now);

        assert!(
            matches!(admission, Admission::Replay(_)),
            "unexpected: {admission:?}"
        );
    }

    #[test]
    fn open_should_drop_entries_older_than_retention() {
        let fixture = Fixture::new();
        fixture.complete(&fixture.open(fixture.now), "d1", "{}");
        let later = fixture.now + RETENTION + Duration::from_secs(1);

        let admission = fixture.admit(&fixture.open(later), "d1", later);

        assert!(
            matches!(admission, Admission::Fresh(_)),
            "unexpected: {admission:?}"
        );
    }
}
