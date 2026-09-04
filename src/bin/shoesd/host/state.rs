//! The record of what has been applied, on disk.
//!
//! A daemon that dies with routes installed leaves the Mac offline, and that
//! is the failure in this design with the worst blast radius: the user cannot
//! reach the network, which is also how they would fetch a fix.
//!
//! So everything the daemon is about to change is written down first, and
//! `launchd`'s `KeepAlive` restarts the process within seconds of a crash.
//! Recovery reads the file, undoes what it describes, and deletes it -- before
//! anything else, and without anyone logging in.
//!
//! Written *before* the change rather than after. The window where a change
//! exists and is unrecorded is then closed rather than merely small, and the
//! cost is that the file can describe a change that never happened. That is
//! the safe direction, and it is why every revert step has to be idempotent.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Route;

/// What was applied, in the order it was applied.
///
/// Reverting walks it backwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedState {
    /// The tunnel interface, for diagnostics and for the log line a recovery
    /// prints. Not load-bearing on revert: routes carry their own `Via`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,

    /// Routes, in application order.
    #[serde(default)]
    pub routes: Vec<Route>,

    /// What DNS looked like before, and where to put it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsBackup>,
}

/// The resolvers a service had before the daemon touched it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsBackup {
    /// The service id the resolvers belong to. Kept rather than re-derived on
    /// revert: the primary service can change while the tunnel is up -- that
    /// is what moving from Wi-Fi to Ethernet does -- and restoring to whatever
    /// is primary *then* would write one service's resolvers onto another.
    pub service: String,
    /// What was there. Empty means the service had none configured, and
    /// restoring empty is how it gets back to that.
    pub servers: Vec<IpAddr>,
}

impl AppliedState {
    /// Whether there is anything to undo.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.dns.is_none()
    }

    /// Write the record, atomically.
    ///
    /// Through a temporary file and a rename, because the alternative is a
    /// crash during the write leaving a half-written file -- and the one
    /// moment this file is read is after exactly that kind of crash. A
    /// truncated record is worse than none: it parses as fewer routes than
    /// were applied, and the revert silently skips the rest.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;

        let temporary = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&json)?;
            // The rename is atomic but says nothing about the bytes having
            // reached the disk; without this the record can survive as an
            // empty file across a power loss.
            file.sync_all()?;
        }
        std::fs::rename(&temporary, path)?;

        // Root-only. It describes the machine's network configuration, which
        // is not secret, but nothing else has any business rewriting the list
        // of things this daemon will undo as root.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Read a record left by a previous run, if there is one.
    ///
    /// A file that will not parse is reported rather than ignored. It means a
    /// previous run applied changes this one cannot describe, and continuing
    /// as though the machine were clean would strand them.
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::other(format!("{} is not readable: {e}", path.display())))
    }

    /// Forget the record. Called once the machine is back to how it was.
    pub fn clear(path: &Path) -> std::io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Via, route_for_test};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn populated() -> AppliedState {
        AppliedState {
            interface: Some("utun4".to_string()),
            routes: vec![
                route_for_test("0.0.0.0", 1, Via::Interface("utun4".into())),
                route_for_test("128.0.0.0", 1, Via::Interface("utun4".into())),
            ],
            dns: Some(DnsBackup {
                service: "ABC-123".to_string(),
                servers: vec![ip("192.168.1.1")],
            }),
        }
    }

    #[test]
    fn a_record_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");

        let state = populated();
        state.save(&path).unwrap();

        let read = AppliedState::load(&path).unwrap().expect("it was written");
        assert_eq!(read, state);
    }

    /// The ordinary case on a machine that has never crashed, and it must not
    /// be an error -- every start reads this file.
    #[test]
    fn no_record_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            AppliedState::load(&dir.path().join("nothing.json")).unwrap(),
            None
        );
    }

    /// A record that will not parse means a previous run changed the machine
    /// in a way this one cannot describe. Treating that as "nothing to undo"
    /// would strand those changes -- which, for routes, means a Mac that
    /// cannot reach the network and no record of why.
    #[test]
    fn an_unreadable_record_is_reported_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        std::fs::write(&path, b"{ this is not json").unwrap();

        let err = AppliedState::load(&path).expect_err("a corrupt record must be reported");
        assert!(
            err.to_string().contains("not readable"),
            "the message should name the file: {err}"
        );
    }

    #[test]
    fn clearing_a_record_that_is_not_there_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        AppliedState::clear(&dir.path().join("nothing.json")).unwrap();
    }

    /// Nothing but root has any business rewriting the list of changes a root
    /// daemon will undo.
    #[test]
    #[cfg(unix)]
    fn a_record_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");
        populated().save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    /// Saving twice must leave one readable record, not a directory full of
    /// temporary files -- and the second must win.
    #[test]
    fn saving_again_replaces_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("applied.json");

        populated().save(&path).unwrap();
        let second = AppliedState {
            interface: Some("utun7".to_string()),
            ..Default::default()
        };
        second.save(&path).unwrap();

        assert_eq!(AppliedState::load(&path).unwrap().unwrap(), second);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn an_empty_record_has_nothing_to_undo() {
        assert!(AppliedState::default().is_empty());
        assert!(!populated().is_empty());
    }
}
