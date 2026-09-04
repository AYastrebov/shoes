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

/// And the directory: enter and list for root and that group, nothing for
/// anyone else. See [`ensure_parent`].
const SOCKET_DIR_MODE: u32 = 0o750;

/// Bind the control socket at `path` with group `group_gid` and mode 0660.
///
/// The owner is left as the creating process, which in production is root.
///
/// The listener is returned only once the ownership and mode are in place,
/// and the socket is never reachable by anyone else even for the instant
/// before that -- see the umask note below.
pub fn bind(path: &Path, group_gid: u32) -> std::io::Result<tokio::net::UnixListener> {
    remove_stale(path)?;

    ensure_parent(path, group_gid)?;

    let listener = tokio::net::UnixListener::bind(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not bind {}: {e}", path.display()))
    })?;

    // `chown` first, `chmod` second, and the order is the point: the group is
    // given access only once the file is already theirs to reach. Widening the
    // mode first would hand it to whatever group the socket was created under.
    set_group(path, group_gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not set mode on {}: {e}", path.display()),
        )
    })?;

    Ok(listener)
}

/// Make sure the socket's directory exists and, where this created it, that
/// only root and the group can enter it.
///
/// This is what closes the window between `bind` and the `chmod` above. `bind`
/// takes no mode -- the kernel creates the socket with `0777 & ~umask` -- so
/// for an instant the file exists at whatever the inherited umask allowed, and
/// a connection made in that instant is queued on this same listener and
/// survives the mode being corrected.
///
/// The obvious fix, narrowing the umask around `bind`, is wrong in this
/// process: the umask is global to it, and while it is narrowed any other
/// thread creating a file gets that mode too. The supervisor's record
/// directory came out `0600` -- no execute, so nothing could be written inside
/// it -- which is how this was found.
///
/// A directory nobody else can traverse closes the same window with no global
/// state: reaching a socket requires search permission on every directory
/// above it, so during that instant the only processes that can connect are
/// the ones already entitled to.
///
/// Only a directory this created is tightened. `--socket /tmp/x.sock` must not
/// silently chmod `/tmp`, and there the umask -- 022 on every runner and login
/// shell, giving `0755`, which denies the write that `connect` needs -- is
/// what is left. The shipped default lives in its own directory for exactly
/// this reason.
fn ensure_parent(path: &Path, group_gid: u32) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(parent).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not create {}: {e}", parent.display()),
        )
    })?;
    set_group(parent, group_gid)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(SOCKET_DIR_MODE)).map_err(
        |e| {
            std::io::Error::new(
                e.kind(),
                format!("could not set mode on {}: {e}", parent.display()),
            )
        },
    )
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

    /// The window between `bind` and the `chmod` is closed by the directory,
    /// not by the socket's own mode -- reaching a socket needs search
    /// permission on every directory above it.
    #[tokio::test]
    async fn bind_creates_a_directory_others_cannot_enter() {
        let gid = unsafe { libc::getgid() } as u32;
        let dir = std::env::temp_dir().join(format!("shoesd-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("shoesd.sock");

        let listener = bind(&path, gid).expect("bind creates the directory it needs");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_DIR_MODE, "got {mode:o}");
        assert_eq!(
            mode & 0o007,
            0,
            "nobody outside the group may even enter it"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory that already exists is left exactly as it is.
    ///
    /// `--socket /tmp/x.sock` must not silently chmod `/tmp`, which would be a
    /// root process tightening a directory the whole system shares.
    #[tokio::test]
    async fn bind_does_not_touch_a_directory_it_did_not_create() {
        let gid = unsafe { libc::getgid() } as u32;
        let dir = std::env::temp_dir().join(format!("shoesd-existing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("shoesd.sock");

        let listener = bind(&path, gid).expect("an existing directory is fine");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "left alone, not tightened: {mode:o}");

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
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
