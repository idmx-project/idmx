//! SMTP hand-off: the message goes to the local MTA (Postfix or anything with
//! a sendmail-compatible command), which owns SMTP queueing from there on.

use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use idmx_core::envelope::{Envelope, ReversePath};

/// Why the MTA did not take the message.
#[derive(Debug, thiserror::Error)]
pub enum HandOffError {
    /// The sendmail command cannot be run or fed.
    #[error("running sendmail command: {0}")]
    Io(#[from] io::Error),
    /// The sendmail command refused the message.
    #[error("sendmail command failed: {0}")]
    Failed(ExitStatus),
}

/// Submits `message` with the envelope of `envelope` through `sendmail`
/// (`sendmail -i -f <from> -- <to>...`, message on standard input).
///
/// # Errors
///
/// Returns [`HandOffError`] if the command cannot be run or exits unsuccessfully;
/// the message is then still the caller's responsibility.
pub fn hand_off(sendmail: &Path, envelope: &Envelope, message: &[u8]) -> Result<(), HandOffError> {
    let from = match envelope.from() {
        ReversePath::Mailbox(mailbox) => mailbox.to_string(),
        ReversePath::Null => "<>".to_owned(),
    };
    let mut child = Command::new(sendmail)
        .args(["-i", "-f", &from, "--"])
        .args(envelope.to().iter().map(ToString::to_string))
        .stdin(Stdio::piped())
        .spawn()?;

    // Dropping the pipe at the end of the block signals end of message.
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(message),
        None => Ok(()),
    };
    let status = child.wait()?;
    written?;

    if status.success() {
        Ok(())
    } else {
        Err(HandOffError::Failed(status))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A fake sendmail that records its arguments and input next to itself.
    fn fake_sendmail(dir: &Path, exit_code: u8) -> std::path::PathBuf {
        let path = dir.join("sendmail");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$0.args\"\ncat >\"$0.input\"\nexit {exit_code}\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn envelope(from: ReversePath) -> Envelope {
        Envelope::new(from, vec!["bob@legacy.example".parse().unwrap()]).unwrap()
    }

    #[test]
    fn hand_off_should_pass_envelope_as_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let sendmail = fake_sendmail(dir.path(), 0);
        let from = ReversePath::Mailbox("alice@sender.example".parse().unwrap());

        hand_off(&sendmail, &envelope(from), b"Subject: x\r\n\r\n").unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("sendmail.args")).unwrap(),
            "-i\n-f\nalice@sender.example\n--\nbob@legacy.example\n"
        );
    }

    #[test]
    fn hand_off_should_pass_message_bytes_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let sendmail = fake_sendmail(dir.path(), 0);

        hand_off(
            &sendmail,
            &envelope(ReversePath::Null),
            b"Subject: x\r\n\r\n.\r\n",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("sendmail.input")).unwrap(),
            b"Subject: x\r\n\r\n.\r\n"
        );
    }

    #[test]
    fn hand_off_should_use_angle_brackets_for_null_reverse_path() {
        let dir = tempfile::tempdir().unwrap();
        let sendmail = fake_sendmail(dir.path(), 0);

        hand_off(&sendmail, &envelope(ReversePath::Null), b"").unwrap();

        let args = std::fs::read_to_string(dir.path().join("sendmail.args")).unwrap();
        assert!(args.starts_with("-i\n-f\n<>\n"), "{args}");
    }

    #[test]
    fn hand_off_should_fail_when_command_exits_unsuccessfully() {
        let dir = tempfile::tempdir().unwrap();
        let sendmail = fake_sendmail(dir.path(), 75);

        let result = hand_off(&sendmail, &envelope(ReversePath::Null), b"");

        assert!(matches!(result, Err(HandOffError::Failed(_))));
    }
}
