//! Pinned positive discovery results (`spec/discovery.md` §3), kept in one
//! JSON file.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use idmx_core::domain::Domain;
use serde::{Deserialize, Serialize};

/// Why the pin file could not be used.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// The pin file cannot be read or written.
    #[error("pin file {}: {source}", path.display())]
    Io {
        /// The pin file.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// The pin file is not what this module wrote.
    #[error("pin file {}: {source}", path.display())]
    Parse {
        /// The pin file.
        path: PathBuf,
        /// The underlying failure.
        source: serde_json::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Pin {
    /// Endpoint authorities (`host[:port]`) in priority order.
    authorities: Vec<String>,
    /// Seconds since the Unix epoch.
    expires: u64,
}

/// Recipient domain → pinned endpoints, persisted on every change.
#[derive(Debug)]
pub struct PinStore {
    /// `None`: pins live only as long as this value.
    path: Option<PathBuf>,
    pins: HashMap<Domain, Pin>,
}

impl PinStore {
    /// A store that is never persisted, for one-shot senders.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            pins: HashMap::new(),
        }
    }

    /// Loads `path`; a missing file is an empty store.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] if the file exists but cannot be read or parsed.
    pub fn open(path: &Path) -> Result<Self, PinError> {
        let pins = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| PinError::Parse {
                path: path.to_owned(),
                source,
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(source) => {
                return Err(PinError::Io {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        Ok(Self {
            path: Some(path.to_owned()),
            pins,
        })
    }

    /// The pinned endpoint authorities of `domain`, if its pin is still valid.
    #[must_use]
    pub fn lookup(&self, domain: &Domain, now: SystemTime) -> Option<&[String]> {
        self.pins
            .get(domain)
            .filter(|pin| pin.expires > unix_seconds(now))
            .map(|pin| pin.authorities.as_slice())
    }

    /// Sets or refreshes the pin after a successful capabilities fetch;
    /// `max_age` of `None` removes it.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] if the file cannot be written.
    pub fn set(
        &mut self,
        domain: &Domain,
        authorities: &[String],
        max_age: Option<Duration>,
        now: SystemTime,
    ) -> Result<(), PinError> {
        match max_age {
            Some(max_age) => {
                let pin = Pin {
                    authorities: authorities.to_vec(),
                    expires: unix_seconds(now).saturating_add(max_age.as_secs()),
                };
                self.pins.insert(domain.clone(), pin);
            }
            None => {
                if self.pins.remove(domain).is_none() {
                    return Ok(());
                }
            }
        }
        self.persist()
    }

    fn persist(&self) -> Result<(), PinError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let json = serde_json::to_vec_pretty(&self.pins).map_err(|source| PinError::Parse {
            path: path.clone(),
            source,
        })?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, json)
            .and_then(|()| std::fs::rename(&temporary, path))
            .map_err(|source| PinError::Io {
                path: path.clone(),
                source,
            })
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_hours(1);

    fn domain() -> Domain {
        "receiver.example".parse().unwrap()
    }

    fn authorities() -> Vec<String> {
        vec!["idmx.receiver.example:8443".to_owned()]
    }

    fn store(dir: &tempfile::TempDir) -> PinStore {
        PinStore::open(&dir.path().join("pins.json")).unwrap()
    }

    #[test]
    fn lookup_should_return_none_when_never_pinned() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(store(&dir).lookup(&domain(), SystemTime::now()), None);
    }

    #[test]
    fn lookup_should_return_pinned_authorities_before_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let mut pins = store(&dir);
        pins.set(&domain(), &authorities(), Some(HOUR), now)
            .unwrap();

        assert_eq!(
            pins.lookup(&domain(), now + HOUR / 2),
            Some(authorities().as_slice())
        );
    }

    #[test]
    fn lookup_should_return_none_after_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let mut pins = store(&dir);
        pins.set(&domain(), &authorities(), Some(HOUR), now)
            .unwrap();

        assert_eq!(pins.lookup(&domain(), now + HOUR), None);
    }

    #[test]
    fn set_should_remove_the_pin_when_max_age_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let mut pins = store(&dir);
        pins.set(&domain(), &authorities(), Some(HOUR), now)
            .unwrap();
        pins.set(&domain(), &authorities(), None, now).unwrap();

        assert_eq!(pins.lookup(&domain(), now), None);
    }

    #[test]
    fn open_should_restore_pins_written_earlier() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        store(&dir)
            .set(&domain(), &authorities(), Some(HOUR), now)
            .unwrap();

        assert_eq!(
            store(&dir).lookup(&domain(), now),
            Some(authorities().as_slice())
        );
    }

    #[test]
    fn open_should_fail_when_file_is_not_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pins.json"), "not json").unwrap();

        let result = PinStore::open(&dir.path().join("pins.json"));

        assert!(matches!(result, Err(PinError::Parse { .. })));
    }
}
