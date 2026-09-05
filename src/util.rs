use std::time::SystemTime;

use tokio::io::AsyncWriteExt;

/// Seconds since the Unix epoch.
///
/// Several protocols stamp a handshake with the current time and reject a peer
/// whose clock is too far off. A clock set before 1970 is a broken clock rather
/// than something to panic over: these run on every connection, and the mobile
/// profile is built with `panic = "abort"`, where a panic ends the process
/// rather than the connection. A broken clock fails the handshake either way,
/// so an error says the same thing and says it usefully.
#[inline]
pub fn unix_time_secs() -> std::io::Result<u64> {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .map(|since_epoch| since_epoch.as_secs())
        .map_err(|e| std::io::Error::other(format!("system clock is before the Unix epoch: {e}")))
}

/// A zeroed buffer of `len` bytes.
///
/// This used to be `with_capacity` + `set_len`, handing out uninitialized
/// memory as `&mut [u8]` — formally undefined behaviour, and the only `unsafe`
/// in this crate. Zeroing costs nothing that matters here: large allocations
/// come from the allocator as untouched zero pages the kernel materialises on
/// first write, which is exactly the laziness the resident-memory numbers in
/// MOBILE.md rely on, and no per-packet path allocates at all.
#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

// a cancellable alternative to AsyncWriteExt::write_all
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}

/// smoltcp time from the monotonic clock.
///
/// `smoltcp::time::Instant::now()` reads the wall clock, and both virtual
/// stacks used it for every poll and timer decision. A backward NTP step
/// -- routine on the wake after a long sleep -- then stalls every
/// retransmit and keepalive timer for the size of the correction, and a
/// forward step fires them all at once. Anchored to the wall clock once,
/// at first use, so the absolute values stay legible in diagnostics;
/// after that only the monotonic clock moves it.
///
/// Lives here rather than in either stack: the AmneziaWG netstack is not
/// gated on the TUN module, and a clock is nobody's device concern.
pub fn smol_now() -> smoltcp::time::Instant {
    static BASE: std::sync::OnceLock<(std::time::Instant, smoltcp::time::Instant)> =
        std::sync::OnceLock::new();
    let (mono, smol) =
        *BASE.get_or_init(|| (std::time::Instant::now(), smoltcp::time::Instant::now()));
    smol + smoltcp::time::Duration::from_micros(mono.elapsed().as_micros() as u64)
}

/// Raw errnos whose numbers differ between libc and WinSock.
///
/// `libc::EMSGSIZE`/`libc::EINVAL` on Windows are the CRT errnos, which a
/// socket never produces -- matching them there leaves the branch dead
/// code on a shipping target. The trap is documented once, here; a new
/// errno comparison should add its constant here rather than rediscover
/// it (the accept-exhaustion set in tcp_server.rs carries its own cfg for
/// the same reason).
#[cfg(windows)]
pub const EMSGSIZE_RAW: i32 = 10040; // WSAEMSGSIZE
#[cfg(not(windows))]
pub const EMSGSIZE_RAW: i32 = libc::EMSGSIZE;

/// See [`EMSGSIZE_RAW`].
#[cfg(windows)]
pub const EINVAL_RAW: i32 = 10022; // WSAEINVAL
#[cfg(not(windows))]
pub const EINVAL_RAW: i32 = libc::EINVAL;

/// See [`EMSGSIZE_RAW`].
#[cfg(windows)]
pub const ENOBUFS_RAW: i32 = 10055; // WSAENOBUFS
#[cfg(not(windows))]
pub const ENOBUFS_RAW: i32 = libc::ENOBUFS;

/// How loudly to log a connection that ended with `e`.
///
/// One table instead of a per-file copy: the accept loops had grown
/// their own, it missed `NotConnected`, and every new kind would have
/// had to be remembered in each. (The resolver's refresh table and the
/// AWG recv classifier stay separate on purpose -- they answer
/// different questions than "how loudly", and coupling the decisions
/// would let a logging tweak change retry behavior.)
///
/// - `Debug`: client-side teardowns -- scanners probing the port, peers
///   resetting mid-handshake, half-closed sockets. Routine, continuous,
///   and worthless above debug on any internet-facing listener.
/// - `Info`, not debug, for timeouts: a half-open probe and a stalled
///   upstream produce the same `TimedOut` here, and release builds
///   compile debug out entirely (`release_max_level_info` in
///   Cargo.toml) -- an upstream serving nothing must not leave an empty
///   log while every connection dies.
/// - `Error` for the rest.
pub fn connection_end_level(e: &std::io::Error) -> log::Level {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionAborted | ConnectionReset | UnexpectedEof | BrokenPipe | NotConnected => {
            log::Level::Debug
        }
        TimedOut => log::Level::Info,
        _ => log::Level::Error,
    }
}

/// Concurrent proxied connections one listener will hold. Acquired
/// before accept, so past the cap the kernel backlog queues instead of
/// the process's fd table filling -- an unbounded spawn-per-connection
/// is how a connection flood turns into an EMFILE spin. Applied by the
/// TCP, unix-socket, and QUIC accept loops alike; the permit rides
/// inside the connection (PermitStream, or the QUIC connection task) so
/// it tracks the socket's lifetime, not the setup future's.
///
/// Per LISTENER: a config with many listeners can still out-provision
/// RLIMIT_NOFILE in aggregate. A process-wide budget derived from the
/// rlimit is the recorded follow-up in the roadmap.
pub const MAX_INFLIGHT_PER_LISTENER: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    /// Seconds, not milliseconds. Protocols compare this against a peer's
    /// stamp within a window of tens of seconds, so the wrong unit would put
    /// every handshake outside it - and the unit is invisible in a u64.
    #[test]
    fn test_unix_time_secs_is_in_seconds() {
        let now = unix_time_secs().expect("this machine's clock is after 1970");
        // 2020-01-01 and 2100-01-01.
        assert!(
            (1_577_836_800..4_102_444_800).contains(&now),
            "{now} is not a plausible time in seconds"
        );
    }
}
