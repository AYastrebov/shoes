//! Binding the control socket, with the ownership it needs.
//!
//! Two things the upstream tonic example does not do and a root daemon must.
//! `UnixListener::bind` fails with `EADDRINUSE` on a socket file a crash left
//! behind, so a stale path is removed first. And `bind` honours the process
//! umask rather than taking a mode, so ownership and permissions are set
//! explicitly -- between `bind` and that, the socket exists with whatever the
//! umask allowed, which is why nothing accepts on it until this returns.
//!
//! Windows is the same socket -- AF_UNIX, which Windows 10 1803+ has -- and the
//! same sequence: remove a stale socket and only a socket, create the
//! directory and restrict it only if this created it, bind, restrict the
//! socket before anything accepts. What differs is confined to the small
//! per-platform section below: how a socket is recognised on disk, how access
//! is restricted (a DACL rather than chown/chmod), and how accepted connections
//! reach tonic. Not a named pipe: the consumer is a JVM, and grpc-java has no
//! pipe transport. See docs/specs/2026-10-06-windows-privileged-daemon.md.

use std::path::Path;

/// Bind the control socket at `path`, restricted to `access`.
///
/// On Unix `access` is the group from `--group` and the socket ends up mode
/// 0660; on Windows it is unit, and the socket gets a DACL admitting
/// authenticated users to *connect* -- who may then *call* is `auth`'s
/// question, per request, exactly as group membership is on Unix.
///
/// The owner is left as the creating process, which in production is root
/// (or `LocalSystem`).
///
/// The listener is returned only once access is restricted, and the socket is
/// never reachable by anyone else even for the instant before that -- see
/// [`ensure_parent`].
pub fn bind(path: &Path, access: Access) -> std::io::Result<platform::Listener> {
    remove_stale(path)?;

    ensure_parent(path, access)?;

    let listener = platform::bind(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not bind {}: {e}", path.display()))
    })?;

    platform::restrict_socket(path, access)?;

    Ok(listener)
}

/// What tonic serves: the listener's accepted connections, as a stream.
pub use platform::incoming;

/// What [`bind`] restricts the socket to: a group on Unix, nothing on Windows.
pub type Access = platform::Access;

/// Make sure the socket's directory exists and, where this created it, that
/// only root and the group can enter it.
///
/// This is what closes the window between `bind` and the restriction above.
/// `bind` takes no mode -- the kernel creates the socket with `0777 & ~umask`
/// -- so for an instant the file exists at whatever the inherited umask
/// allowed, and a connection made in that instant is queued on this same
/// listener and survives the mode being corrected.
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
///
/// On Windows the shipped directory is created by `install`, under
/// `%ProgramFiles%` where no standard user can create it first; this branch
/// then only runs for `shoesd run` against a path of its own.
fn ensure_parent(path: &Path, access: Access) -> std::io::Result<()> {
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
    platform::restrict_dir(parent, access)
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

    if !platform::is_socket(path, &metadata) {
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

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::Path;

    /// The group allowed to connect.
    pub type Access = u32;
    pub type Listener = tokio::net::UnixListener;

    /// Owner-and-group read/write, nothing for anyone else. The group is the
    /// one `--group` named; see `auth`.
    pub(super) const SOCKET_MODE: u32 = 0o660;

    /// And the directory: enter and list for root and that group, nothing for
    /// anyone else. See `ensure_parent`.
    pub(super) const SOCKET_DIR_MODE: u32 = 0o750;

    pub fn bind(path: &Path) -> std::io::Result<Listener> {
        tokio::net::UnixListener::bind(path)
    }

    pub fn incoming(listener: Listener) -> tokio_stream::wrappers::UnixListenerStream {
        tokio_stream::wrappers::UnixListenerStream::new(listener)
    }

    /// The file type says so outright on Unix; the path is for Windows' sake,
    /// where the type does not.
    pub fn is_socket(_path: &Path, metadata: &std::fs::Metadata) -> bool {
        metadata.file_type().is_socket()
    }

    pub fn restrict_socket(path: &Path, group_gid: Access) -> std::io::Result<()> {
        // `chown` first, `chmod` second, and the order is the point: the group
        // is given access only once the file is already theirs to reach.
        // Widening the mode first would hand it to whatever group the socket
        // was created under.
        set_group(path, group_gid)?;
        set_mode(path, SOCKET_MODE)
    }

    pub fn restrict_dir(path: &Path, group_gid: Access) -> std::io::Result<()> {
        set_group(path, group_gid)?;
        set_mode(path, SOCKET_DIR_MODE)
    }

    fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("could not set mode on {}: {e}", path.display()),
            )
        })
    }

    /// Give the socket its group, leaving the owner alone.
    ///
    /// `chown` with `-1` for the uid means "do not change the owner", and that
    /// is the right call rather than a shortcut. The daemon runs as root, so
    /// the socket it just created is already root-owned and setting it again
    /// would be a no-op; asking to *change* an owner to root is a privileged
    /// operation that only root may perform, so spelling it out would make
    /// this the one step that cannot run outside production -- and it is the
    /// step whose correctness most wants a test.
    fn set_group(path: &Path, group_gid: u32) -> std::io::Result<()> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path contains a NUL byte",
            )
        })?;

        // SAFETY: `c_path` is a valid NUL-terminated string for the duration
        // of the call, and both ids are plain scalars. `(uid_t)-1` is the
        // documented "unchanged" sentinel.
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
}

/// The Windows half: the same contract, different mechanisms.
///
/// tokio's `UnixListener` is `cfg(unix)`, and std's `TcpListener::accept`
/// parses the peer address as inet and fails on AF_UNIX. So `uds_windows`
/// binds and accepts, on a thread of its own, and each accepted socket is
/// handed to tokio as a `TcpStream`: reads and writes go through mio's AFD
/// polling, which does not care about the address family.
///
/// Who connected is read here, at accept, while the PID the kernel reports is
/// still the connecting process's, and carried into every request as
/// [`PeerInfo`] -- the counterpart of tonic's `UdsConnectInfo`, which is
/// where the Unix peer credentials come from.
#[cfg(windows)]
mod platform {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{FromRawSocket, IntoRawSocket, RawSocket};
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tonic::transport::server::Connected;

    use crate::auth::PeerIdentity;

    /// Nothing to name: who may connect is fixed by [`SOCKET_SDDL`], and who
    /// may call by `auth`. A type rather than `()` so the shared signature
    /// reads the same on every platform.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Access;
    pub type Listener = uds_windows::UnixListener;

    /// `_WSAIOR(IOC_VENDOR, 256)`, from `afunix.h`: the connected peer's PID.
    /// Not in `windows-sys`, whose metadata omits it.
    const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;

    /// `FILE_ATTRIBUTE_REPARSE_POINT`. An AF_UNIX socket on Windows is a
    /// reparse point -- but so are symlinks, junctions and several other
    /// kinds of file, so this alone does not make something a socket.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    /// `IO_REPARSE_TAG_AF_UNIX`, from `ntifs.h`: the tag that makes a reparse
    /// point a socket, and the only one `remove_stale` may delete.
    const IO_REPARSE_TAG_AF_UNIX: u32 = 0x8000_0023;

    /// The socket file: SYSTEM and Administrators fully, every authenticated
    /// user enough to connect. Protected (`P`), so nothing inherited widens it.
    pub(super) const SOCKET_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    /// A directory this created: SYSTEM and Administrators fully, users may
    /// traverse and read -- the counterpart of 0750 root:group, with the
    /// group's membership checked per call instead of by the file system.
    const DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)";

    /// How many accepted connections may wait for the server before accept
    /// parks.
    const ACCEPT_BACKLOG: usize = 16;

    pub fn bind(path: &Path) -> std::io::Result<Listener> {
        uds_windows::UnixListener::bind(path)
    }

    /// A reparse point whose tag says AF_UNIX socket. The attribute is checked
    /// first because it is free; the tag is what decides, since a symlink or
    /// junction carries the same attribute and deleting one with SYSTEM's
    /// rights is exactly what `remove_stale` exists to refuse.
    pub fn is_socket(path: &Path, metadata: &std::fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            && reparse_tag(path) == Some(IO_REPARSE_TAG_AF_UNIX)
    }

    /// The reparse tag of `path`, which `FindFirstFileW` reports in
    /// `dwReserved0` for a reparse point. `None` when it cannot be read --
    /// which `is_socket` then treats as "not a socket", the safe answer.
    fn reparse_tag(path: &Path) -> Option<u32> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            FindClose, FindFirstFileW, WIN32_FIND_DATAW,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: a NUL-terminated path; `data` is written on success and the
        // handle is closed below.
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let handle = unsafe { FindFirstFileW(wide.as_ptr(), &mut data) };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: a find handle from the call above, closed once.
        unsafe { FindClose(handle) };
        Some(data.dwReserved0)
    }

    pub fn restrict_socket(path: &Path, _: Access) -> std::io::Result<()> {
        crate::win_security::set_file_dacl(path, SOCKET_SDDL)
    }

    pub fn restrict_dir(path: &Path, _: Access) -> std::io::Result<()> {
        crate::win_security::set_file_dacl(path, DIR_SDDL)
    }

    /// Who the peer on a connection is, or why that could not be learned.
    ///
    /// `Err` is kept rather than turned into a dropped connection: a refusal
    /// must reach the client as `PERMISSION_DENIED`, not as a daemon that
    /// seems absent -- the reason `auth` gives on Unix.
    #[derive(Clone, Debug)]
    pub struct PeerInfo(pub Result<PeerIdentity, String>);

    /// An accepted connection.
    pub struct Connection {
        stream: tokio::net::TcpStream,
        pub(super) peer: PeerInfo,
    }

    impl Connected for Connection {
        type ConnectInfo = PeerInfo;

        fn connect_info(&self) -> PeerInfo {
            self.peer.clone()
        }
    }

    impl AsyncRead for Connection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Connection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    /// Connections accepted on a dedicated thread.
    ///
    /// The thread blocks in `accept` and ends once the server has gone away --
    /// on the next connection after that, since nothing interrupts a blocking
    /// accept. For the daemon, process exit is the same moment.
    ///
    /// Must be called inside the runtime that will serve: each socket is
    /// registered with that runtime's reactor.
    pub fn incoming(
        listener: Listener,
    ) -> tokio_stream::wrappers::ReceiverStream<std::io::Result<Connection>> {
        let (tx, rx) = tokio::sync::mpsc::channel(ACCEPT_BACKLOG);
        let runtime = tokio::runtime::Handle::current();
        std::thread::Builder::new()
            .name("shoesd-accept".into())
            .spawn(move || {
                loop {
                    let accepted = listener.accept().and_then(|(stream, _)| {
                        // Taken as soon as accept returns: the peer existed
                        // before this moment, which is what lets the identity
                        // lookup refuse a process that took its PID later.
                        let accepted_at = crate::auth::now();
                        connection(stream.into_raw_socket(), accepted_at, &runtime)
                    });
                    if tx.blocking_send(accepted).is_err() {
                        return;
                    }
                }
            })
            .expect("spawning the accept thread");
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    fn connection(
        socket: RawSocket,
        accepted_at: u64,
        runtime: &tokio::runtime::Handle,
    ) -> std::io::Result<Connection> {
        // Identify first, before the socket changes hands: the PID is the
        // kernel's answer for this connection, read as close to accept as
        // possible, and the process found must predate the accept -- see
        // `PeerIdentity::of_connected_process`.
        let peer = PeerInfo(
            peer_pid(socket)
                .and_then(|pid| PeerIdentity::of_connected_process(pid, accepted_at))
                .map_err(|e| e.to_string()),
        );

        // SAFETY: `socket` came from `into_raw_socket` on the accepted stream
        // and nothing else owns it; the `TcpStream` takes that ownership.
        let std_stream = unsafe { std::net::TcpStream::from_raw_socket(socket) };
        std_stream.set_nonblocking(true)?;
        let _entered = runtime.enter();
        let stream = tokio::net::TcpStream::from_std(std_stream)?;
        Ok(Connection { stream, peer })
    }

    fn peer_pid(socket: RawSocket) -> std::io::Result<u32> {
        use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl};

        let mut pid: u32 = 0;
        let mut returned: u32 = 0;
        // SAFETY: an output-only ioctl into a u32 it may write four bytes of;
        // no overlapped I/O, no completion routine.
        let rc = unsafe {
            WSAIoctl(
                socket as usize,
                SIO_AF_UNIX_GETPEERPID,
                std::ptr::null(),
                0,
                (&mut pid as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc != 0 {
            // SAFETY: plain FFI call.
            let code = unsafe { WSAGetLastError() };
            return Err(std::io::Error::from_raw_os_error(code));
        }
        Ok(pid)
    }
}

#[cfg(windows)]
pub use platform::PeerInfo;

#[cfg(test)]
mod tests {
    use super::*;

    /// Short on purpose: `sun_path` is 108 bytes on Windows as elsewhere, and
    /// a deep temp directory is enough to exceed it.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shoesd-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("shoesd.sock")
    }

    /// Whatever `bind` needs on this platform to succeed as the test user.
    #[cfg(unix)]
    fn own_access() -> platform::Access {
        // SAFETY: plain FFI call.
        unsafe { libc::getgid() as u32 }
    }

    #[cfg(windows)]
    fn own_access() -> platform::Access {
        platform::Access
    }

    /// A crash leaves the socket file behind, and launchd restarts the daemon
    /// within seconds. If that restart failed with EADDRINUSE the daemon
    /// would be down until someone logged in — which is exactly when nobody
    /// can, because the routes are still installed.
    #[tokio::test]
    async fn bind_replaces_a_socket_left_by_a_crash() {
        let path = scratch("stale");

        let first = bind(&path, own_access()).expect("first bind");
        // Dropping the listener does not unlink the path — that is what makes
        // this the ordinary case rather than an exotic one.
        drop(first);
        assert!(platform::is_socket(
            &path,
            &std::fs::symlink_metadata(&path).unwrap()
        ));

        let second = bind(&path, own_access()).expect("a stale socket must not block a restart");
        drop(second);
        let _ = std::fs::remove_file(&path);
    }

    /// Refusing here is the difference between "the daemon did not start" and
    /// "a root process deleted the file its configuration pointed at".
    #[test]
    fn bind_refuses_to_delete_something_that_is_not_a_socket() {
        let path = scratch("regular-file");
        std::fs::write(&path, b"not a socket").unwrap();

        let err = bind(&path, own_access()).expect_err("a regular file must not be unlinked");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            std::fs::read(&path).unwrap() == b"not a socket",
            "the file must still be there"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The whole point of `bind`: after it returns, the socket is not
    /// readable or writable by anyone outside the group.
    ///
    /// The group is not asserted here — chown to a group the test user does
    /// not own needs root, so `bind` is exercised with the caller's own gid
    /// and the mode is what this checks. The ownership half is covered by the
    /// live run in the plan.
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_leaves_the_socket_unreadable_by_others() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch("mode");

        let listener = bind(&path, own_access()).expect("bind should succeed in a temp dir");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, platform::SOCKET_MODE, "got {mode:o}");

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// The window between `bind` and the `chmod` is closed by the directory,
    /// not by the socket's own mode -- reaching a socket needs search
    /// permission on every directory above it.
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_creates_a_directory_others_cannot_enter() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("shoesd-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("shoesd.sock");

        let listener = bind(&path, own_access()).expect("bind creates the directory it needs");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, platform::SOCKET_DIR_MODE, "got {mode:o}");
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
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_does_not_touch_a_directory_it_did_not_create() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("shoesd-existing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("shoesd.sock");

        let listener = bind(&path, own_access()).expect("an existing directory is fine");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "left alone, not tightened: {mode:o}");

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A junction carries the same reparse attribute a socket does. Deleting
    /// one with SYSTEM's rights is what the tag check exists to prevent; a
    /// junction rather than a symlink because creating one needs no privilege.
    #[cfg(windows)]
    #[test]
    fn bind_refuses_to_delete_a_junction() {
        let path = scratch("junction");
        let target = path.with_file_name("target-dir");
        std::fs::create_dir_all(&target).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&path)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J failed: {made:?}");

        let err = bind(&path, own_access()).expect_err("a junction is not ours to delete");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(path.exists(), "the junction must still be there");

        let _ = std::fs::remove_dir(&path);
        let _ = std::fs::remove_dir_all(&target);
    }

    /// The socket's DACL is the one asked for, protected from inheritance.
    #[cfg(windows)]
    #[tokio::test]
    async fn bind_gives_the_socket_its_dacl() {
        let path = scratch("dacl");

        let listener = bind(&path, own_access()).expect("bind should succeed in a temp dir");
        let sddl = crate::win_security::file_dacl_sddl(&path).expect("readable");
        assert!(sddl.starts_with("D:P"), "protected: {sddl}");
        assert!(
            sddl.contains(";;;AU)"),
            "authenticated users may connect: {sddl}"
        );

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// The accept path end to end: a real client connects, and the connection
    /// arrives carrying *this* process as its peer.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_accepted_connection_knows_its_peer() {
        use tokio_stream::StreamExt;

        let path = scratch("peer");
        let mut connections = incoming(bind(&path, own_access()).unwrap());

        let client_path = path.clone();
        let _client = std::thread::spawn(move || uds_windows::UnixStream::connect(client_path))
            .join()
            .unwrap()
            .expect("connect");

        let connection = connections.next().await.unwrap().expect("accepted");
        let identity = connection.peer.0.expect("the peer is identifiable");
        assert_eq!(identity.pid, std::process::id());

        let _ = std::fs::remove_file(&path);
    }
}
