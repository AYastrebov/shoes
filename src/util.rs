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
