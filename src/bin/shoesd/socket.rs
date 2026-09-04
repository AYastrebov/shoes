//! Binding the control socket, with the ownership it needs.
//!
//! Two things the upstream tonic example does not do and a root daemon must.
//! `UnixListener::bind` fails with `EADDRINUSE` on a socket file a crash left
//! behind, so a stale path is removed first. And `bind` honours the process
//! umask rather than taking a mode, so ownership and permissions are set
//! explicitly -- between `bind` and that, the socket exists with whatever the
//! umask allowed, which is why nothing accepts on it until this returns.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

/// Owner-and-group read/write, nothing for anyone else. The group is the one
/// `--group` named; see `auth`.
const SOCKET_MODE: u32 = 0o660;

/// Bind the control socket at `path` with group `group_gid` and mode 0660.
///
/// The owner is left as the creating process, which in production is root.
///
/// The listener is returned only once the permissions are in place, so a
/// caller cannot accidentally accept on a world-writable socket.
pub fn bind(path: &Path, group_gid: u32) -> std::io::Result<tokio::net::UnixListener> {
    remove_stale(path)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("could not create {}: {e}", parent.display()),
            )
        })?;
    }

    let listener = tokio::net::UnixListener::bind(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not bind {}: {e}", path.display()))
    })?;

    // Order matters: narrow the mode first, then hand the group its access.
    // The other way round leaves a window in which the socket is reachable by
    // the group *and* whatever the umask left open.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not set mode on {}: {e}", path.display()),
        )
    })?;
    set_group(path, group_gid)?;

    Ok(listener)
}

/// Remove a socket file left behind by a crash.
///
/// Only a socket. If the path is a regular file, a directory or a symlink,
/// something other than this daemon owns it, and unlinking it would be this
/// program deleting a file it was misconfigured to point at -- with root's
/// privileges. Refusing is the only safe answer.
fn remove_stale(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove it",
                path.display()
            ),
        ));
    }

    std::fs::remove_file(path)
}

/// Give the socket its group, leaving the owner alone.
///
/// `chown` with `-1` for the uid means "do not change the owner", and that is
/// the right call rather than a shortcut. The daemon runs as root, so the
/// socket it just created is already root-owned and setting it again would be
/// a no-op; asking to *change* an owner to root is a privileged operation that
/// only root may perform, so spelling it out would make this the one step that
/// cannot run outside production -- and it is the step whose correctness most
/// wants a test.
fn set_group(path: &Path, group_gid: u32) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path contains a NUL byte",
        )
    })?;

    // SAFETY: `c_path` is a valid NUL-terminated string for the duration of
    // the call, and both ids are plain scalars. `(uid_t)-1` is the documented
    // "unchanged" sentinel.
    let rc = unsafe {
        libc::chown(
            c_path.as_ptr(),
            u32::MAX as libc::uid_t,
            group_gid as libc::gid_t,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            e.kind(),
            format!(
                "could not set the group of {} to {group_gid}: {e}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shoesd-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("shoesd.sock")
    }

    /// The whole point of `bind`: after it returns, the socket is not
    /// readable or writable by anyone outside the group.
    ///
    /// The group is not asserted here — chown to a group the test user does
    /// not own needs root, so `bind` is exercised with the caller's own gid
    /// and the mode is what this checks. The ownership half is covered by the
    /// live run in the plan.
    #[tokio::test]
    async fn bind_leaves_the_socket_unreadable_by_others() {
        let path = scratch("mode");
        let gid = unsafe { libc::getgid() } as u32;

        let listener = bind(&path, gid).expect("bind should succeed in a temp dir");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE, "got {mode:o}");

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// A crash leaves the socket file behind, and launchd restarts the daemon
    /// within seconds. If that restart failed with EADDRINUSE the daemon
    /// would be down until someone logged in — which is exactly when nobody
    /// can, because the routes are still installed.
    #[tokio::test]
    async fn bind_replaces_a_socket_left_by_a_crash() {
        let path = scratch("stale");
        let gid = unsafe { libc::getgid() } as u32;

        let first = bind(&path, gid).expect("first bind");
        // Dropping the listener does not unlink the path — that is what makes
        // this the ordinary case rather than an exotic one.
        drop(first);
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );

        let second = bind(&path, gid).expect("a stale socket must not block a restart");
        drop(second);
        let _ = std::fs::remove_file(&path);
    }

    /// Refusing here is the difference between "the daemon did not start" and
    /// "a root process deleted the file its configuration pointed at".
    #[test]
    fn bind_refuses_to_delete_something_that_is_not_a_socket() {
        let path = scratch("regular-file");
        std::fs::write(&path, b"not a socket").unwrap();

        let err = bind(&path, 0).expect_err("a regular file must not be unlinked");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            std::fs::read(&path).unwrap() == b"not a socket",
            "the file must still be there"
        );

        let _ = std::fs::remove_file(&path);
    }
}
