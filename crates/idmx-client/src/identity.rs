//! The sending domain's signing identity: private key plus `keyid`.

use std::path::Path;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use idmx_core::key::{KeyId, KeyRecord};

/// Errors from loading an [`Identity`].
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The key file cannot be read.
    #[error("reading private key: {0}")]
    Read(#[from] std::io::Error),
    /// The key file is not a PKCS#8 PEM Ed25519 private key.
    #[error("private key is not an Ed25519 key in PKCS#8 PEM format")]
    Format,
}

/// What a sender signs with. Create the key with
/// `openssl genpkey -algorithm ed25519 -out key.pem`.
pub struct Identity {
    key: SigningKey,
    keyid: KeyId,
}

impl Identity {
    /// Pairs an in-memory key with the `keyid` it is published under.
    #[must_use]
    pub fn new(key: SigningKey, keyid: KeyId) -> Self {
        Self { key, keyid }
    }

    /// Loads a PKCS#8 PEM private key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if the file is unreadable or not such a key.
    pub fn from_pem_file(path: &Path, keyid: KeyId) -> Result<Self, IdentityError> {
        let pem = std::fs::read_to_string(path)?;
        let key = SigningKey::from_pkcs8_pem(&pem).map_err(|_| IdentityError::Format)?;
        Ok(Self::new(key, keyid))
    }

    /// The private key.
    #[must_use]
    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    /// The name the public key is published under.
    #[must_use]
    pub fn keyid(&self) -> &KeyId {
        &self.keyid
    }

    /// The TXT record value to publish at [`Self::keyid`].
    #[must_use]
    pub fn key_record(&self) -> String {
        KeyRecord::render(&self.key.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openssl genpkey -algorithm ed25519` output for the RFC 8032 TEST 1 seed.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n\
        -----END PRIVATE KEY-----\n";

    fn keyid() -> KeyId {
        "s1._idmxkey.sender.example".parse().unwrap()
    }

    #[test]
    fn from_pem_file_should_load_openssl_generated_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, TEST_KEY_PEM).unwrap();

        let identity = Identity::from_pem_file(&path, keyid()).unwrap();

        assert_eq!(
            identity.key_record(),
            "v=IDMX1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        );
    }

    #[test]
    fn from_pem_file_should_fail_when_file_is_not_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, "not a key").unwrap();

        let result = Identity::from_pem_file(&path, keyid());

        assert!(matches!(result, Err(IdentityError::Format)));
    }

    #[test]
    fn from_pem_file_should_fail_when_file_missing() {
        let result = Identity::from_pem_file(Path::new("/nonexistent/key.pem"), keyid());

        assert!(matches!(result, Err(IdentityError::Read(_))));
    }
}
