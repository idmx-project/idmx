//! Local delivery into a Maildir (`new/` via `tmp/` and an atomic rename).

use std::io;
use std::path::{Path, PathBuf};

/// Writes `message` into the Maildir at `maildir` under `unique_name`.
///
/// `unique_name` must be a single path component; callers build it from
/// validated parts only.
///
/// # Errors
///
/// Returns the I/O error if a directory or the file cannot be written.
pub async fn deliver(maildir: &Path, unique_name: &str, message: &[u8]) -> io::Result<PathBuf> {
    for subdir in ["tmp", "new", "cur"] {
        tokio::fs::create_dir_all(maildir.join(subdir)).await?;
    }
    let tmp = maildir.join("tmp").join(unique_name);
    let new = maildir.join("new").join(unique_name);

    tokio::fs::write(&tmp, message).await?;
    tokio::fs::rename(&tmp, &new).await?;
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deliver_should_place_message_in_new() {
        let dir = tempfile::tempdir().unwrap();

        let path = deliver(dir.path(), "1.key.0", b"message").await.unwrap();

        assert_eq!(
            (path.parent(), std::fs::read(&path).unwrap().as_slice()),
            (
                Some(dir.path().join("new").as_path()),
                b"message".as_slice()
            )
        );
    }

    #[tokio::test]
    async fn deliver_should_leave_tmp_empty() {
        let dir = tempfile::tempdir().unwrap();

        deliver(dir.path(), "1.key.0", b"message").await.unwrap();

        assert_eq!(
            std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
            0
        );
    }
}
