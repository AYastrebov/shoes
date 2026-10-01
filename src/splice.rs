//! A relay between two TCP sockets that never brings the bytes into this
//! process: `splice(2)` moves them socket to pipe to socket inside the kernel.
//!
//! The ordinary relay reads into a buffer and writes it out again, two copies
//! across the user-kernel boundary for every byte. When both ends are nothing
//! more than sockets -- a SOCKS, HTTP or redirect inbound sent out directly --
//! none of that is needed, and it is where sing-box, which splices, carried
//! twice what shoes did at well under half the CPU (`scripts/bench/README.md`).
//!
//! A stream volunteers through [`AsyncStream::plain_tcp`]. A wrapper that
//! only counts or holds a permit passes its socket through and asks to be told
//! the byte counts instead; anything that transforms or buffers says nothing,
//! and the relay copies as before.
//!
//! [`AsyncStream::plain_tcp`]: crate::async_stream::AsyncStream::plain_tcp

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

use tokio::io::Interest;
use tokio::net::TcpStream;

use crate::async_stream::PlainTcp;

/// What one `splice` call is asked to move. A pipe holds 64 KiB unless grown,
/// so this is a ceiling the pipe sets rather than this number.
const SPLICE_LEN: usize = 1 << 20;

/// What a pipe is grown to, where the system allows it. One socket buffer's
/// worth per call instead of sixteen pages.
const PIPE_SIZE: libc::c_int = 256 * 1024;

/// Pipes kept for reuse.
///
/// A pipe is held only while bytes are in motion: taken when a source turns
/// readable, returned when it is empty and the source has run dry. So an idle
/// connection holds none, which matters because an unprivileged user's pipes
/// are budgeted in pages (`/proc/sys/fs/pipe-user-pages-soft`) and past the
/// budget every new pipe is one page.
const POOL_MAX: usize = 32;

/// Rounds of a busy direction between yields to the runtime. The readiness
/// calls do not charge tokio's cooperative budget, so a connection that is
/// never blocked would otherwise keep its thread.
const ROUNDS_PER_YIELD: usize = 32;

static POOL: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl Pipe {
    fn take() -> io::Result<Self> {
        if let Some(pipe) = POOL.lock().unwrap().pop() {
            return Ok(pipe);
        }
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a two-element array, which is what pipe2 writes.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just returned by pipe2 and are owned
        // by nothing else.
        let pipe = unsafe {
            Self {
                read: OwnedFd::from_raw_fd(fds[0]),
                write: OwnedFd::from_raw_fd(fds[1]),
            }
        };
        // Best effort: refused past the user's page budget, and the default
        // size works.
        // SAFETY: a plain fcntl on a descriptor this function owns.
        unsafe { libc::fcntl(pipe.write.as_raw_fd(), libc::F_SETPIPE_SZ, PIPE_SIZE) };
        Ok(pipe)
    }

    /// Give back a pipe that is known to be empty. One with bytes still in it
    /// is dropped instead, which closes it: the next user must not find
    /// another connection's data.
    fn give_back(self) {
        let mut pool = POOL.lock().unwrap();
        if pool.len() < POOL_MAX {
            pool.push(self);
        }
    }
}

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: both descriptors are open for the duration of the call, and
    // null offsets mean "the descriptor's own position", which is the only
    // kind a socket or a pipe has.
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Why a burst of splicing stopped.
enum Burst {
    /// The source has nothing more for now.
    Dry,
    /// The source's peer has finished sending.
    Eof,
    /// The kernel will not splice from this socket at all; nothing was moved.
    Unsupported,
}

/// Move bytes from `src` to `dst` through `pipe` until the source runs dry or
/// ends. On `Ok` the pipe is empty.
async fn burst(src: &PlainTcp<'_>, dst: &PlainTcp<'_>, pipe: &Pipe) -> io::Result<Burst> {
    let (src_fd, dst_fd) = (src.socket.as_raw_fd(), dst.socket.as_raw_fd());
    let mut rounds = 0;
    let mut moved_any = false;
    loop {
        // The pipe is empty here, so "would block" can only mean the socket.
        let filled = match src.socket.try_io(Interest::READABLE, || {
            splice(src_fd, pipe.write.as_raw_fd(), SPLICE_LEN)
        }) {
            Ok(0) => return Ok(Burst::Eof),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Burst::Dry),
            Err(e)
                if !moved_any && matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) =>
            {
                return Ok(Burst::Unsupported);
            }
            Err(e) => return Err(e),
        };
        moved_any = true;
        src.count_read(filled);

        let mut left = filled;
        while left > 0 {
            match dst.socket.try_io(Interest::WRITABLE, || {
                splice(pipe.read.as_raw_fd(), dst_fd, left)
            }) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    left -= n;
                    dst.count_written(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    dst.socket.writable().await?;
                }
                Err(e) => return Err(e),
            }
        }

        rounds += 1;
        if rounds % ROUNDS_PER_YIELD == 0 {
            tokio::task::yield_now().await;
        }
    }
}

/// One direction of the relay: `src` to `dst` until `src`'s peer finishes,
/// then the same finish passed on to `dst`.
async fn one_way(src: &PlainTcp<'_>, dst: &PlainTcp<'_>) -> io::Result<()> {
    loop {
        src.socket.readable().await?;
        let pipe = Pipe::take()?;
        // An error leaves bytes in the pipe, so it is dropped, not returned;
        // so is one this future is cancelled while holding.
        match burst(src, dst, &pipe).await? {
            Burst::Dry => pipe.give_back(),
            Burst::Eof => {
                pipe.give_back();
                break;
            }
            Burst::Unsupported => {
                pipe.give_back();
                copy_one_way(src, dst).await?;
                break;
            }
        }
    }
    shutdown_write(dst.socket);
    Ok(())
}

/// The same direction with a buffer, for a socket the kernel will not splice
/// from. Not expected on any kernel this runs on; here so that such a kernel
/// costs speed rather than the connection.
async fn copy_one_way(src: &PlainTcp<'_>, dst: &PlainTcp<'_>) -> io::Result<()> {
    let mut buf = vec![0u8; crate::buffer_sizing::default_relay_buffer_size()];
    loop {
        src.socket.readable().await?;
        let n = match src.socket.try_read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        src.count_read(n);
        let mut written = 0;
        while written < n {
            dst.socket.writable().await?;
            match dst.socket.try_write(&buf[written..n]) {
                Ok(m) => {
                    written += m;
                    dst.count_written(m);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Tell `socket`'s peer that nothing more is coming, leaving the other
/// direction open. A failure means the peer is already gone, which the other
/// direction will find out for itself.
fn shutdown_write(socket: &TcpStream) {
    // SAFETY: a plain shutdown on a descriptor the caller keeps open.
    unsafe { libc::shutdown(socket.as_raw_fd(), libc::SHUT_WR) };
}

/// Relay between two sockets until both directions have finished, the way
/// `copy_bidirectional` does: a finish on one side is passed to the other and
/// the opposite direction keeps running; an error ends both.
pub async fn splice_bidirectional(a: PlainTcp<'_>, b: PlainTcp<'_>) -> io::Result<()> {
    tokio::try_join!(one_way(&a, &b), one_way(&b, &a))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::async_stream::TransferCounter;

    #[derive(Default)]
    struct Counted {
        read: AtomicU64,
        written: AtomicU64,
    }

    impl TransferCounter for Counted {
        fn bytes_read(&self, n: u64) {
            self.read.fetch_add(n, Ordering::Relaxed);
        }
        fn bytes_written(&self, n: u64) {
            self.written.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// A connected pair of sockets over loopback.
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialled, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (dialled.unwrap(), accepted.unwrap().0)
    }

    /// Bytes nothing would produce by accident, so a relay that dropped,
    /// duplicated or reordered any would be caught.
    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ ((i >> 8) as u8))
            .collect()
    }

    /// The relay between two connections: everything written at one far end
    /// arrives at the other, in both directions at once, a finish is passed
    /// on while the other direction keeps running, and the counters see
    /// every byte.
    #[tokio::test]
    async fn bytes_cross_both_ways_and_a_finish_is_passed_on() {
        let (mut client, relay_client_side) = pair().await;
        let (relay_server_side, mut server) = pair().await;
        let (near, far) = (Counted::default(), Counted::default());

        let relay = tokio::spawn(async move {
            let (near, far) = (near, far);
            let a = PlainTcp {
                socket: &relay_client_side,
                counters: vec![&near],
            };
            let b = PlainTcp {
                socket: &relay_server_side,
                counters: vec![&far],
            };
            splice_bidirectional(a, b).await.unwrap();
            (
                near.read.load(Ordering::Relaxed),
                near.written.load(Ordering::Relaxed),
                far.read.load(Ordering::Relaxed),
                far.written.load(Ordering::Relaxed),
            )
        });

        // More than any pipe or socket buffer holds, so the relay has to
        // block and resume in both directions.
        let up = pattern(3 * 1024 * 1024 + 17, 1);
        let down = pattern(2 * 1024 * 1024 + 5, 2);

        let (up_sent, down_sent) = (up.clone(), down.clone());
        let client_task = tokio::spawn(async move {
            let (mut read, mut write) = client.split();
            let writer = async {
                write.write_all(&up_sent).await.unwrap();
                // Finish sending; the download must still arrive in full.
                write.shutdown().await.unwrap();
            };
            let reader = async {
                let mut got = Vec::new();
                read.read_to_end(&mut got).await.unwrap();
                got
            };
            tokio::join!(writer, reader).1
        });
        let server_task = tokio::spawn(async move {
            let (mut read, mut write) = server.split();
            let writer = async {
                write.write_all(&down_sent).await.unwrap();
                write.shutdown().await.unwrap();
            };
            let reader = async {
                let mut got = Vec::new();
                read.read_to_end(&mut got).await.unwrap();
                got
            };
            tokio::join!(writer, reader).1
        });

        let client_got = client_task.await.unwrap();
        let server_got = server_task.await.unwrap();
        assert!(client_got == down, "the download arrived changed");
        assert!(server_got == up, "the upload arrived changed");

        let (near_read, near_written, far_read, far_written) = relay.await.unwrap();
        assert_eq!(near_read, up.len() as u64);
        assert_eq!(far_written, up.len() as u64);
        assert_eq!(far_read, down.len() as u64);
        assert_eq!(near_written, down.len() as u64);
    }

    /// A peer that vanishes ends the relay with an error rather than leaving
    /// it waiting on a direction that can no longer finish.
    #[tokio::test]
    async fn a_reset_ends_the_relay() {
        let (client, relay_client_side) = pair().await;
        let (relay_server_side, _server) = pair().await;

        let relay = tokio::spawn(async move {
            let a = PlainTcp {
                socket: &relay_client_side,
                counters: Vec::new(),
            };
            let b = PlainTcp {
                socket: &relay_server_side,
                counters: Vec::new(),
            };
            splice_bidirectional(a, b).await
        });

        // Linger of zero turns the close into a reset.
        socket2::SockRef::from(&client)
            .set_linger(Some(std::time::Duration::ZERO))
            .unwrap();
        drop(client);

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("the relay never ended")
            .unwrap();
        assert!(result.is_err(), "a reset must not look like a clean finish");
    }

    /// A pipe that went back to the pool is empty: a connection that takes
    /// it next must not read another connection's bytes out of it.
    #[tokio::test]
    async fn a_pooled_pipe_is_empty() {
        let (mut client, relay_client_side) = pair().await;
        let (relay_server_side, mut server) = pair().await;
        let relay = tokio::spawn(async move {
            let a = PlainTcp {
                socket: &relay_client_side,
                counters: Vec::new(),
            };
            let b = PlainTcp {
                socket: &relay_server_side,
                counters: Vec::new(),
            };
            splice_bidirectional(a, b).await
        });
        client.write_all(b"through the pipe").await.unwrap();
        let mut got = [0u8; 16];
        server.read_exact(&mut got).await.unwrap();
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();

        let pipe = Pipe::take().unwrap();
        let mut byte = [0u8; 1];
        // SAFETY: a read into a one-byte buffer from a descriptor owned here.
        let n = unsafe { libc::read(pipe.read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        assert_eq!(n, -1, "the pipe held bytes");
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
    }
}
