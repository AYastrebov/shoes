//! Noticing that the routing table moved, over netlink.
//!
//! An `AF_NETLINK` socket subscribed to the route and link groups, read purely
//! as a signal. The daemon never parses the message to work out *what*
//! changed: deciding that from a routing delta is where this class of code goes
//! wrong, and it is unnecessary, because re-reading the table and comparing
//! gives the same answer and cannot drift. So every message means the same
//! thing here -- "look again" -- and the supervisor's handler is idempotent.
//!
//! This is the mechanism `ip monitor route link` is built on, and the same pair
//! of multicast groups it subscribes to.
//!
//! The macOS twin of this file is `host/macos/monitor.rs`; the shape is
//! deliberately identical, because the difference between `PF_ROUTE` and
//! `AF_NETLINK` here is one `bind` and nothing else.

use std::os::unix::io::RawFd;

/// How long to wait after a burst before reporting it.
///
/// A single network change produces a flurry of messages -- the link going
/// down, addresses being removed, the new default arriving -- and re-applying
/// on each would mean re-reading the table a dozen times while it is still
/// settling.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// And again, a moment later.
///
/// The macOS rationale for this -- the system restoring its own resolvers
/// asynchronously, a little after the change -- does not apply to the
/// systemd-resolved backend, whose per-link configuration nothing else touches.
/// It applies squarely to the direct `/etc/resolv.conf` backend, which contends
/// with whatever else on the host writes that file: NetworkManager and
/// `netconfig` both rewrite it on their own schedule rather than ours, so a DNS
/// re-apply that runs only once can be undone immediately afterwards with
/// nothing left to notice it.
///
/// Keeping one code path costs two extra `resolvectl` calls per network change
/// on hosts that do not need them. That is cheaper than two monitors.
const SECOND_LOOK: std::time::Duration = std::time::Duration::from_secs(2);

/// Watch the routing table, calling `on_change` when it moves.
///
/// The thread runs for the life of the process. It is detached deliberately:
/// there is nothing to join it for, and the daemon's shutdown path has to be
/// able to finish without waiting on a socket read that only the kernel can
/// end.
pub fn spawn(on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    let fd = open_route_socket()?;

    // Owned before the thread exists, so a `spawn` that fails closes the
    // descriptor rather than leaking it. The guard is moved into the closure,
    // which is dropped un-run on that path.
    let guard = FdGuard(fd);

    std::thread::Builder::new()
        .name("shoesd-route-monitor".to_owned())
        .spawn(move || {
            let _guard = guard;
            // Nothing here parses a message, so a netlink message longer than
            // this is truncated and that costs nothing -- the signal is that
            // one arrived at all.
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

                // The second look, for the resolvers something else on the host
                // puts back on its own schedule rather than ours.
                std::thread::sleep(SECOND_LOOK);
                drain(fd, &mut buffer);
                on_change();
            }
        })?;

    Ok(())
}

/// Open the netlink socket and subscribe it to route and link changes.
///
/// The bind is not optional and is the one thing here that `PF_ROUTE` does not
/// need: a netlink socket with no `nl_groups` joins no multicast group and so
/// receives nothing at all, silently, forever. That makes this the one half of
/// the monitor that can fail before the thread starts, which is why it is
/// separate from [`spawn`] -- see the test below.
///
/// `NETLINK_NO_ENOBUFS` is deliberately *not* set. That option exists to
/// suppress exactly the error this monitor wants to see; suppressing it would
/// turn a dropped burst into silence instead of into a re-read.
fn open_route_socket() -> std::io::Result<RawFd> {
    // SAFETY: a plain socket call with constant arguments.
    let fd: RawFd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Owned from here on, so a failing bind does not leak the descriptor.
    let socket = FdGuard(fd);

    // SAFETY: `sockaddr_nl` is a plain C struct for which all-zero is a valid
    // value, and it carries a private padding field, so it is built by zeroing
    // rather than by a literal.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // `nl_pid` stays zero so the kernel picks the port id. Choosing one by hand
    // means colliding with any other netlink socket in the process.
    address.nl_groups = (libc::RTMGRP_IPV4_ROUTE | libc::RTMGRP_LINK) as u32;

    // SAFETY: `address` is an initialised `sockaddr_nl` that outlives the call,
    // the length passed is its own size, and `fd` is open and owned by
    // `socket`.
    let bound = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(address) as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        // Read errno before `socket` drops: the close in its `Drop` would be
        // the last syscall otherwise, and errno is per-thread, not per-fd.
        let error = std::io::Error::last_os_error();
        return Err(error);
    }

    Ok(socket.into_raw())
}

/// Whether a read error is one to carry on from.
///
/// `ENOBUFS` has no `ErrorKind` of its own, so it is matched by errno. It is
/// also the one that matters, and `netlink(7)` is where the rule comes from
/// rather than analogy with `PF_ROUTE`: "The kernel can't send a netlink
/// message if the socket buffer is full: the message will be dropped and the
/// kernel and the user-space process will no longer have the same view of
/// kernel state. It is up to the application to detect when this happens (via
/// the ENOBUFS error returned by recvmsg(2)) and resynchronize."
///
/// Resynchronising is exactly what this monitor does anyway -- it re-reads the
/// table rather than tracking a delta -- which is why losing messages costs
/// nothing here.
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

impl FdGuard {
    /// Hand the descriptor to a caller that will close it instead.
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: the fd was opened here and is not shared.
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening *and binding* the socket must work for an unprivileged process,
    /// because a failure here would be the daemon's first act and the message
    /// would name the wrong thing. Neither needs privilege -- `ip monitor`
    /// subscribes to these same groups as any user -- but the bind is the half
    /// with no macOS counterpart, so it is the half worth asserting.
    ///
    /// `open_route_socket` rather than `spawn`: the thread `spawn` starts is
    /// detached and blocks in `read` until the kernel says otherwise, so a test
    /// that called it would leave a thread running for the rest of the binary,
    /// waking on every routing change a CI runner happens to have. The macOS
    /// twin of this test does call its spawning function and leaks exactly that
    /// thread -- finding 3 of `shoes-agent-prompt-daemon-review-2.md`. This
    /// checks the half that can fail; that the loop then reads is the live
    /// run's to show.
    ///
    /// `getsockname` is asserted as well as the open, because a socket that was
    /// never bound -- or bound with the groups left at zero -- opens perfectly
    /// and then receives nothing for the life of the process, which is the
    /// failure this whole function exists to prevent and the one an `fd >= 0`
    /// check cannot see. The kernel reports the joined mask back in
    /// `nl_groups`, and a bound socket has a non-zero `nl_pid`. Whether a
    /// message then arrives is still the live run's to show: producing one
    /// needs `CAP_NET_ADMIN`.
    #[test]
    fn the_netlink_socket_opens_and_binds_without_privilege() {
        let fd =
            open_route_socket().expect("a bound NETLINK_ROUTE socket is available to any process");
        assert!(fd >= 0);
        let _guard = FdGuard(fd);

        // SAFETY: all-zero is a valid `sockaddr_nl`, and the kernel is given
        // the true size of the buffer it may write into.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: `address` and `length` outlive the call, `length` describes
        // `address`, and `fd` is open and owned by `_guard`.
        let named = unsafe {
            libc::getsockname(
                fd,
                std::ptr::addr_of_mut!(address) as *mut libc::sockaddr,
                &mut length,
            )
        };
        assert_eq!(named, 0, "{}", std::io::Error::last_os_error());

        assert_ne!(address.nl_pid, 0, "the socket was never bound");
        assert_eq!(
            address.nl_groups,
            (libc::RTMGRP_IPV4_ROUTE | libc::RTMGRP_LINK) as u32,
            "the socket joined the wrong multicast groups"
        );
    }

    /// `ENOBUFS` is the one that matters: the thread stops reading for over two
    /// seconds per event, so a burst on a busy network overflows the socket
    /// buffer -- and `netlink(7)` says the kernel drops the message and reports
    /// it here. Treating that as fatal would end the monitor after the first
    /// Wi-Fi-to-Ethernet move, which is the event it exists for.
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
