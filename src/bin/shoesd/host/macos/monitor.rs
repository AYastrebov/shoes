//! Noticing that the routing table moved.
//!
//! A `PF_ROUTE` socket, read purely as a signal. The daemon never parses the
//! message to work out *what* changed: deciding that from a routing delta is
//! where this class of code goes wrong, and it is unnecessary, because
//! re-reading the table and comparing gives the same answer and cannot drift.
//! So every message means the same thing here -- "look again" -- and the
//! supervisor's handler is idempotent.
//!
//! This is the mechanism `route -n monitor` is built on, and the one wg-quick's
//! `darwin.bash` uses for the same purpose.

use std::os::unix::io::RawFd;

/// How long to wait after a burst before reporting it.
///
/// A single network change produces a flurry of messages -- the interface
/// going down, addresses being removed, the new default arriving -- and
/// re-applying on each would mean re-reading the table a dozen times while it
/// is still settling.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// And again, a moment later.
///
/// macOS restores the host's own resolvers asynchronously a little after a
/// network change, so a DNS re-apply that runs only once can be undone
/// immediately afterwards with nothing left to notice it. wg-quick works
/// around the same behaviour by kicking itself with `SIGALRM` two seconds
/// later; this is that, without the signal.
const SECOND_LOOK: std::time::Duration = std::time::Duration::from_secs(2);

/// Watch the routing table, calling `on_change` when it moves.
///
/// The thread runs for the life of the process. It is detached deliberately:
/// there is nothing to join it for, and the daemon's shutdown path has to be
/// able to finish without waiting on a socket read that only the kernel can
/// end.
pub fn spawn(on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    let fd = open_route_socket()?;

    std::thread::Builder::new()
        .name("shoesd-route-monitor".to_owned())
        .spawn(move || {
            let _guard = FdGuard(fd);
            let mut buffer = [0u8; 4096];

            loop {
                // SAFETY: `buffer` is valid for `len` bytes for the duration of
                // the call, and `fd` is open until `_guard` drops.
                let read = unsafe {
                    libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
                };

                if read < 0 {
                    let error = std::io::Error::last_os_error();
                    if recoverable(&error) {
                        // Notably ENOBUFS. This thread sleeps for over two
                        // seconds per event without reading, so a burst on a
                        // busy network overflows the socket buffer -- and
                        // treating that as fatal would end the monitor after
                        // the first Wi-Fi-to-Ethernet move, which is the exact
                        // event it exists for. The messages are lost either
                        // way and it does not matter: nothing here parses
                        // them, and the re-apply that follows re-reads the
                        // table.
                        continue;
                    }
                    // The socket is gone and reopening it is the job of the
                    // next process. Losing the monitor costs re-application on
                    // a network change, not the session.
                    log::error!("the route monitor stopped: {error}");
                    return;
                }
                if read == 0 {
                    log::error!("the route monitor's socket closed");
                    return;
                }

                // Drain whatever else the kernel has queued for this change
                // before reporting, so a burst becomes one re-apply.
                std::thread::sleep(SETTLE);
                drain(fd, &mut buffer);

                on_change();

                // The second look, for the resolvers macOS puts back on its
                // own schedule rather than ours.
                std::thread::sleep(SECOND_LOOK);
                drain(fd, &mut buffer);
                on_change();
            }
        })?;

    Ok(())
}

/// Open the routing socket.
///
/// Separate from [`spawn`] so a test can check the part that can fail without
/// starting the thread that cannot be stopped -- see the test below.
fn open_route_socket() -> std::io::Result<RawFd> {
    // SAFETY: a plain socket call with constant arguments.
    let fd: RawFd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Whether a read error is one to carry on from.
///
/// `ENOBUFS` has no `ErrorKind` of its own, so it is matched by errno.
fn recoverable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    ) || error.raw_os_error() == Some(libc::ENOBUFS)
}

/// Read and discard whatever is queued, without blocking.
fn drain(fd: RawFd, buffer: &mut [u8]) {
    loop {
        // SAFETY: as in the read above; MSG_DONTWAIT makes it non-blocking, so
        // this cannot park the thread on an empty queue.
        let read = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read <= 0 {
            return;
        }
    }
}

/// Closes the socket when the thread ends.
struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: the fd was opened here and is not shared.
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening the socket must work for an unprivileged process, because a
    /// failure here would be the daemon's first act and the message would name
    /// the wrong thing. Reading it needs no privilege either -- `route -n
    /// monitor` runs as any user.
    ///
    /// `open_route_socket` rather than `spawn`: the thread `spawn` starts is
    /// detached and blocks in `read` until the kernel says otherwise, so a
    /// test that called it would leave a thread running for the rest of the
    /// binary, waking on every routing change a CI runner happens to have.
    /// This checks the half that can fail; that the loop then reads is the
    /// live run's to show.
    #[test]
    fn the_route_socket_opens_without_privilege() {
        let fd = open_route_socket().expect("a PF_ROUTE socket is available to any process");
        assert!(fd >= 0);
        // SAFETY: opened just above and not shared.
        unsafe { libc::close(fd) };
    }

    /// `ENOBUFS` is the one that matters: the thread stops reading for over
    /// two seconds per event, so a burst on a busy network overflows the
    /// socket buffer -- and treating that as fatal would end the monitor after
    /// the first Wi-Fi-to-Ethernet move, which is the event it exists for.
    #[test]
    fn a_full_socket_buffer_is_not_fatal() {
        assert!(recoverable(&std::io::Error::from_raw_os_error(
            libc::ENOBUFS
        )));
        assert!(recoverable(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(recoverable(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));

        // A socket that is genuinely gone is not something to spin on.
        assert!(!recoverable(&std::io::Error::from_raw_os_error(
            libc::EBADF
        )));
        assert!(!recoverable(&std::io::Error::from_raw_os_error(
            libc::ENOTCONN
        )));
    }
}
