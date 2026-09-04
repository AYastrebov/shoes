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
    // SAFETY: a plain socket call with constant arguments.
    let fd: RawFd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

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
                    if error.kind() == std::io::ErrorKind::Interrupted {
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Opening the socket must work for an unprivileged process, because a
    /// failure here would be the daemon's first act and the message would name
    /// the wrong thing. Reading it needs no privilege either -- `route -n
    /// monitor` runs as any user.
    #[test]
    fn the_route_socket_opens_without_privilege() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();

        spawn(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .expect("a PF_ROUTE socket is available to any process");

        // Nothing is asserted about callbacks: the test machine's routing
        // table may sit still for the whole run, and a test that waited for a
        // network change would hang on a quiet host. That the socket opens and
        // the thread starts is what this can honestly check; the rest is the
        // live run's.
    }
}
