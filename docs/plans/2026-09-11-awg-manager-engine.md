# awg-manager engine, slices 1 and 2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The process contract awg-manager holds its engine to (`SIGHUP`, `check`, `version`), and the two transparent-proxy inbounds its tproxy router mode is built on (`redirect` for TCP, `tproxy` for UDP), on Linux.

**Architecture:** `redirect` reads `SO_ORIGINAL_DST` through a new default method on `AsyncStream` implemented for `TcpStream`, and is otherwise a `PortForwardServerHandler` whose target comes from the socket. `tproxy` is the first `Transport::Udp` server: one `IP_TRANSPARENT` listener with `IP_RECVORIGDSTADDR`, demultiplexed by client address into one `UdpRouter` per client over an `AsyncTargetedMessageStream`, replies spoofed through a per-client cache of transparent sockets. Both register at the accept edge like every other inbound.

**Tech Stack:** Rust 2024, tokio (`AsyncFd`), `socket2`, `libc` (all existing deps), the existing `UdpRouter`.

**Spec:** `docs/specs/2026-09-11-awg-manager-engine.md`, slices 1 and 2. The Clash API plan (`docs/plans/2026-09-09-clash-api.md`) is independent; where a task here touches the connection registry it says so, and the touch is the same call the other inbounds make.

## Global Constraints

- **Linux only for the two inbounds.** `redirect` and `tproxy` are refused at validation on every other OS with a message naming Linux; every `libc` call sits under `#[cfg(target_os = "linux")]`, and the config types exist everywhere so a config parses the same on a Mac.
- **Loopback only** (spec, "Security notes"): a `redirect` or `tproxy` bind on a non-loopback address is a validation error.
- **No debounce on `SIGHUP`** (spec, "Slice 1"); `--no-reload` does not disable it.
- **`udp_nat_max` bounds file descriptors**: sessions across all clients of a `tproxy` listener never exceed it; the reply-socket cache is 64 per client and bounded by the same figure in total.
- **Registry**: both inbounds call `connection_registry::register` / `counted` (Clash plan Task 2) if that has landed; if not, they call nothing and the Clash plan's Task 3 adds the calls with the others.
- **Gates for every task:** `cargo fmt --all -- --check`, `cargo clippy --locked --bins --tests -- -D warnings`, `cargo test --locked`, `cargo build --locked --features control-stats`, and on Linux `cargo test --locked -- --ignored tproxy redirect` under `sudo` for the netfilter tests.
- **Environment:** `export PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$PATH`. Commits use `git -c user.email=ayastrebov@gmail.com commit`. No `timeout` on macOS: `perl -e 'alarm 300; exec @ARGV' -- cargo test ...`.

---

## File structure

**New files**
- `src/redirect_handler.rs` — `RedirectServerHandler`.
- `src/tproxy/mod.rs` — `start_tproxy_udp_server`, the demux loop, `TproxyClientStream`, the reply-socket cache.
- `src/tproxy/sys.rs` — the Linux socket calls: transparent bind, `recvmsg` with original destination, `SO_ORIGINAL_DST`.
- `tests/process_contract.rs` — `check`, `version`, `SIGHUP`.
- `tests/transparent.rs` — the netfilter tests, `#[ignore]` unless run as root.

**Modified files**
- `src/main.rs` — subcommands, `SIGHUP` in the serve loop.
- `src/async_stream.rs` — `original_destination` on `AsyncStream`; `TcpStream`, `PermitStream`, `Box<T>` impls.
- `src/connection_registry.rs` (only if landed) — `CountingStream` forwards `original_destination`.
- `src/config/types/server.rs` — `Redirect`, `Tproxy` variants, `Display`.
- `src/config/validate.rs` — OS and bind rules for both; `transport: udp` only with `tproxy`.
- `src/tcp/tcp_server_handler_factory.rs` — `Redirect` arm.
- `src/tcp/tcp_server.rs` — `Transport::Udp` arm.
- `src/routing/udp_router.rs` — `RouterLimits`, `run_udp_routing_with_limits`.
- `src/lib.rs`, `src/main.rs` — module declarations.
- `README.md` — a section for the two inbounds.
- `.github/workflows/test.yml` — the root-gated Linux step.

---

### Task 1: `check`, `version`, and `SIGHUP`

Spec: "Slice 1: the process contract".

**Files:**
- Modify: `src/main.rs:166-210` (argument loop), `:236` (subcommand block), `:409-490` (serve loop), `:520-600` (`ShutdownSignals`)
- Create: `tests/process_contract.rs`

**Status:** done in `66b7b63` on `feature/engine-contract`. The SIGHUP test uses `std::process` with a kill-on-drop guard, because tokio's `process` feature is not enabled in this crate; the Clash plan's Task 8 tests should do the same.

**Interfaces:**
- Produces: `shoes check <config>...` (exit 0/1), `shoes version` (prints `shoes <version>`), and a `ReloadSignal` stream in `main.rs` with `async fn recv(&mut self)` that resolves on `SIGHUP` and pends forever elsewhere.

- [x] **Step 1: Write the failing tests**

```rust
//! The process contract awg-manager holds an engine to. Drives the real
//! binary: these claims are about main.rs.

use std::net::SocketAddr;
use std::process::Stdio;

fn shoes_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_shoes"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn socks_config(port: u16) -> String {
    format!("- address: 127.0.0.1:{port}\n  protocol:\n    type: socks\n")
}

async fn listening(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

async fn wait_until(addr: SocketAddr, up: bool) {
    for _ in 0..100 {
        if listening(addr).await == up {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{addr} never became up={up}");
}

#[test]
fn check_exits_zero_on_a_valid_config_and_one_with_the_error_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.yaml");
    std::fs::write(&good, socks_config(1080)).unwrap();
    let ok = std::process::Command::new(shoes_bin()).arg("check").arg(&good).output().unwrap();
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));

    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "- address: 127.0.0.1:1080\n  protocol:\n    type: nonsense\n").unwrap();
    let err = std::process::Command::new(shoes_bin()).arg("check").arg(&bad).output().unwrap();
    assert_eq!(err.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&err.stderr).contains("nonsense"));
}

#[test]
fn version_prints_the_crate_version() {
    let out = std::process::Command::new(shoes_bin()).arg("version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("shoes {}", env!("CARGO_PKG_VERSION")));
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_immediately_even_with_no_reload() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let first = free_port();
    let second = free_port();
    std::fs::write(&config, socks_config(first)).unwrap();
    let mut child = tokio::process::Command::new(shoes_bin())
        .arg("--no-reload").arg(&config)
        .kill_on_drop(true).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap();
    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    let second_addr: SocketAddr = format!("127.0.0.1:{second}").parse().unwrap();
    wait_until(first_addr, true).await;

    std::fs::write(&config, socks_config(second)).unwrap();
    let started = std::time::Instant::now();
    unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) };
    wait_until(second_addr, true).await;
    wait_until(first_addr, false).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "no debounce on SIGHUP");
    child.kill().await.unwrap();
}
```

`libc` is a normal dependency, so the test can use it; if the integration test cannot see it, add `libc = "*"` under `[dev-dependencies]`.

- [x] **Step 2: Run, expect failure**

Run: `cargo test --locked --test process_contract`
Expected: `check` and `version` fail (unknown argument, exit 1); `sighup` fails (no reload happens).

- [x] **Step 3: Subcommands**

In `main.rs`, right after the option loop ends (before `if args.iter().any(|s| s == "generate-reality-keypair")`):

```rust
    // Subcommands awg-manager's operator already uses by these names:
    // `check <config>` is `--dry-run`, `version` is `--version`.
    if args.first().map(String::as_str) == Some("version") {
        println!("shoes {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.first().map(String::as_str) == Some("check") {
        args.remove(0);
        dry_run = true;
    }
```

The dry-run block already exits 1 and prints `Dry run failed: …` to stderr; it stays.

- [x] **Step 4: `SIGHUP`**

Add beside `ShutdownSignals`:

```rust
/// The operator's reload request. `SIGHUP` on Unix; nothing elsewhere.
struct ReloadSignal {
    #[cfg(unix)]
    hangup: Option<tokio::signal::unix::Signal>,
}

impl ReloadSignal {
    fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let hangup = match signal(SignalKind::hangup()) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("Could not install the SIGHUP handler: {e}");
                    None
                }
            };
            Self { hangup }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        match &mut self.hangup {
            Some(s) => {
                s.recv().await;
            }
            None => futures::future::pending::<()>().await,
        }
        #[cfg(not(unix))]
        futures::future::pending::<()>().await
    }
}
```

In the serve loop, install `let mut reload = ReloadSignal::install();` beside `signals`. Replace the `if reload_state.is_none() { ... }` block and the inner `prepared = loop { ... }` with one loop that treats a `SIGHUP` like a file change with no debounce:

```rust
            prepared = loop {
                // Three ways out of the wait: a file change (debounced), a
                // SIGHUP (immediate: the sender has finished writing), or a
                // stop signal.
                let debounce = tokio::select! {
                    changed = async {
                        match reload_state.as_mut() {
                            Some((_, rx)) => { rx.recv().await.expect("the watcher thread is co-owned"); }
                            None => futures::future::pending::<()>().await,
                        }
                    } => { let _ = changed; true }
                    _ = reload.recv() => false,
                    (what, code) = signals.recv() => shut_down(what, code, join_handles).await,
                };

                let outcome = tokio::select! {
                    outcome = async {
                        if debounce {
                            println!("Configs changed, reloading in 3 seconds..");
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            if let Some((_, rx)) = reload_state.as_mut() {
                                while rx.try_recv().is_ok() {}
                            }
                        } else {
                            println!("Received SIGHUP, reloading..");
                        }
                        prepare_servers(&args, reload_state.as_mut().map(|(w, _)| w)).await
                    } => outcome,
                    (what, code) = signals.recv() => shut_down(what, code, join_handles).await,
                };

                match outcome {
                    Ok(p) => break p,
                    Err(e) => eprintln!("{e}\nKeeping the previous configuration; fix the file to retry."),
                }
            };
```

`join_handles` is moved into `shut_down` in two arms of one loop iteration; the existing code has the same shape and compiles because `shut_down` returns `!`. Keep the `first_launch` handling and the restart code after the loop as they are.

- [x] **Step 5: Run, gates, commit**

```bash
perl -e 'alarm 300; exec @ARGV' -- cargo test --locked --test process_contract
cargo test --locked && cargo clippy --locked --bins --tests -- -D warnings
git add src/main.rs tests/process_contract.rs
git -c user.email=ayastrebov@gmail.com commit -m "shoes: check and version subcommands, SIGHUP reloads without debounce"
```

---

### Task 2: `original_destination` and the `redirect` inbound

Spec: "Slice 2" → "`redirect`".

**Files:**
- Modify: `src/async_stream.rs:173, 235, 313, 528-529`
- Modify: `src/connection_registry.rs` if present (forward the method on `CountingStream`)
- Create: `src/redirect_handler.rs`
- Modify: `src/config/types/server.rs:676-830` (variant, `Display`), `src/config/validate.rs:1596` (arm), `src/tcp/tcp_server_handler_factory.rs:252`
- Modify: `src/lib.rs`, `src/main.rs` (`mod redirect_handler;`)
- Create: `tests/transparent.rs` (first test)

**Interfaces:**
- Produces: `AsyncStream::original_destination(&self) -> Option<SocketAddr>` (default `None`); `ServerProxyConfig::Redirect {}`; `RedirectServerHandler::new(proxy_selector)`.

- [ ] **Step 1: Failing unit test**

In `src/async_stream.rs` tests:

```rust
    /// A socket that was not redirected has no original destination, and a
    /// listener that forwards to "wherever the kernel said" must see None
    /// rather than its own address.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_plain_socket_reports_no_original_destination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert_eq!(accepted.original_destination(), None);
        drop(client);
    }
```

And in `src/redirect_handler.rs` tests, with the crate's `TestStream` or a `tokio::io::duplex` wrapped in a struct whose `original_destination` returns a fixed address:

```rust
    struct Redirected<S>(S, Option<SocketAddr>);
    // AsyncRead/AsyncWrite/AsyncPing forward to .0; AsyncStream overrides original_destination to .1

    #[tokio::test]
    async fn a_redirected_stream_forwards_to_its_original_destination() {
        let (a, _b) = tokio::io::duplex(16);
        let handler = RedirectServerHandler::new(allow_everything());
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        match handler.setup_server_stream(Box::new(Redirected(a, Some(target)))).await.unwrap() {
            TcpServerSetupResult::TcpForward { remote_location, .. } => {
                assert_eq!(remote_location.to_socket_addr_nonblocking(), Some(target));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_stream_without_an_original_destination_is_refused() {
        let (a, _b) = tokio::io::duplex(16);
        let handler = RedirectServerHandler::new(allow_everything());
        let err = handler.setup_server_stream(Box::new(Redirected(a, None))).await.unwrap_err();
        assert!(err.to_string().contains("not redirected"), "{err}");
    }
```

`allow_everything()` is the helper in `src/tcp/tcp_forward.rs` tests; copy it (it is ten lines) rather than making it `pub`.

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --locked original_destination redirect`
Expected: FAIL to compile.

- [ ] **Step 3: The trait method and the Linux impl**

In `src/async_stream.rs`:

```rust
pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {
    /// Where a transparently redirected connection was going before the
    /// kernel sent it here. `Some` only on Linux, only on a socket that NAT
    /// `REDIRECT` delivered; a `redirect` listener refuses anything else.
    fn original_destination(&self) -> Option<std::net::SocketAddr> {
        None
    }
}
```

Every `impl AsyncStream for X {}` in the tree keeps compiling because the method has a default. Add the `TcpStream` impl body:

```rust
impl AsyncStream for TcpStream {
    #[cfg(target_os = "linux")]
    fn original_destination(&self) -> Option<std::net::SocketAddr> {
        crate::tproxy::sys::original_destination(std::os::fd::AsRawFd::as_raw_fd(self))
    }
}
```

`PermitStream`, `Box<T>`, `&mut T`, `OutboundCountingStream` and (if landed) `CountingStream` forward: `fn original_destination(&self) -> Option<SocketAddr> { self.inner.original_destination() }` (`(**self)` for `Box`, `(**self)` for `&mut T`).

Create `src/tproxy/mod.rs` with `pub mod sys;` for now (Task 4 fills the rest) and `src/tproxy/sys.rs`:

```rust
//! The Linux socket calls behind transparent proxying. Every function here
//! is `cfg(target_os = "linux")`; the module exists elsewhere so the paths
//! resolve, and the inbounds are refused at validation there.

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::RawFd;

    // Kernel values, in case the libc crate in use predates a constant.
    pub const SO_ORIGINAL_DST: libc::c_int = 80;
    pub const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
    pub const IP_TRANSPARENT: libc::c_int = 19;
    pub const IP_RECVORIGDSTADDR: libc::c_int = 20;
    pub const IPV6_TRANSPARENT: libc::c_int = 75;
    pub const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    fn v4(sa: &libc::sockaddr_in) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port)))
    }

    fn v6(sa: &libc::sockaddr_in6) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(sa.sin6_addr.s6_addr), u16::from_be(sa.sin6_port), sa.sin6_flowinfo, sa.sin6_scope_id))
    }

    /// `SO_ORIGINAL_DST`: the destination before NAT `REDIRECT`. `None` when
    /// the socket was not redirected (`ENOENT`) or the option is unsupported.
    pub fn original_destination(fd: RawFd) -> Option<SocketAddr> {
        unsafe {
            let mut sa6: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST, &mut sa6 as *mut _ as *mut libc::c_void, &mut len) == 0
                && sa6.sin6_family as libc::c_int == libc::AF_INET6
            {
                return Some(v6(&sa6));
            }
            let mut sa4: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, &mut sa4 as *mut _ as *mut libc::c_void, &mut len) == 0
                && sa4.sin_family as libc::c_int == libc::AF_INET
            {
                return Some(v4(&sa4));
            }
        }
        None
    }

    fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> std::io::Result<()> {
        let rc = unsafe { libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }

    /// `IP_TRANSPARENT` (needs CAP_NET_ADMIN) and, for a listener,
    /// `IP_RECVORIGDSTADDR` so `recvmsg` reports where each datagram was going.
    pub fn make_transparent(fd: RawFd, ipv6: bool, receive_original_destination: bool) -> std::io::Result<()> {
        let (level, transparent, recv) = if ipv6 {
            (libc::SOL_IPV6, IPV6_TRANSPARENT, IPV6_RECVORIGDSTADDR)
        } else {
            (libc::SOL_IP, IP_TRANSPARENT, IP_RECVORIGDSTADDR)
        };
        setsockopt_int(fd, level, transparent, 1).map_err(|e| {
            std::io::Error::new(e.kind(), format!("IP_TRANSPARENT: {e} (this needs CAP_NET_ADMIN)"))
        })?;
        if receive_original_destination {
            setsockopt_int(fd, level, recv, 1)?;
        }
        Ok(())
    }

    /// One datagram with its source and its original destination.
    pub fn recv_with_original_destination(fd: RawFd, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        unsafe {
            let mut source: libc::sockaddr_storage = std::mem::zeroed();
            let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
            // u64-aligned control buffer: cmsghdr needs it.
            let mut control = [0u64; 32];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = &mut source as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let source = match source.ss_family as libc::c_int {
                libc::AF_INET => v4(&*(&source as *const _ as *const libc::sockaddr_in)),
                libc::AF_INET6 => v6(&*(&source as *const _ as *const libc::sockaddr_in6)),
                _ => return Err(std::io::Error::other("unknown address family")),
            };
            let mut destination = None;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == IP_RECVORIGDSTADDR {
                    destination = Some(v4(&*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in)));
                } else if hdr.cmsg_level == libc::SOL_IPV6 && hdr.cmsg_type == IPV6_RECVORIGDSTADDR {
                    destination = Some(v6(&*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6)));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            let _ = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // keep the import honest on both arms
            Ok((n as usize, source, destination))
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
```

Declare `mod tproxy;` in `src/lib.rs` and `src/main.rs` (unconditionally; the file is empty of code off Linux).

- [ ] **Step 4: The handler, the variant, validation, the factory**

`src/redirect_handler.rs`:

```rust
//! The `redirect` inbound: a connection NAT `REDIRECT` delivered, forwarded
//! to where it was going. See docs/specs/2026-09-11-awg-manager-engine.md.

use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct RedirectServerHandler {
    proxy_selector: Arc<ClientProxySelector>,
}

impl RedirectServerHandler {
    pub fn new(proxy_selector: Arc<ClientProxySelector>) -> Self {
        Self { proxy_selector }
    }
}

#[async_trait]
impl TcpServerHandler for RedirectServerHandler {
    async fn setup_server_stream(&self, server_stream: Box<dyn AsyncStream>) -> std::io::Result<TcpServerSetupResult> {
        // A socket with no original destination was not redirected. Forwarding
        // it would send it to this listener's own address: a loop.
        let Some(destination) = server_stream.original_destination() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "connection was not redirected (no SO_ORIGINAL_DST); refusing to forward it",
            ));
        };
        Ok(TcpServerSetupResult::TcpForward {
            remote_location: NetLocation::from(destination),
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            initial_remote_data: None,
            proxy_selector: self.proxy_selector.clone(),
        })
    }
}
```

`NetLocation` has no `From<SocketAddr>` today (`from_ip_addr` is `cfg(test)`); add beside it in `src/address.rs`:

```rust
impl From<std::net::SocketAddr> for NetLocation {
    fn from(addr: std::net::SocketAddr) -> Self {
        let address = match addr.ip() {
            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        Self { address, port: addr.port() }
    }
}
```

`src/config/types/server.rs`: add to the enum, near `PortForward`:

```rust
    /// Transparent TCP: the kernel's NAT `REDIRECT` target. Linux, loopback.
    Redirect {},
    /// Transparent UDP: an `IP_TRANSPARENT` listener with `transport: udp`.
    /// Linux, loopback.
    Tproxy {
        /// Seconds a UDP session may sit idle. sing-box's `udp_timeout`.
        #[serde(default = "default_udp_timeout_secs")]
        udp_timeout: u64,
        /// Live UDP sessions across all clients. sing-box's `udp_nat_max`.
        #[serde(default = "default_udp_nat_max")]
        udp_nat_max: usize,
    },
```

with `fn default_udp_timeout_secs() -> u64 { 300 }` and `fn default_udp_nat_max() -> usize { 4096 }`, and `Display` arms `Self::Redirect { .. } => write!(f, "Redirect")`, `Self::Tproxy { .. } => write!(f, "TPROXY")`. `Redirect {}` with braces so `type: redirect` parses as a unit-like tagged variant the way the others do.

`src/config/validate.rs`, in `validate_server_config` (after the transport checks around `:850`):

```rust
    let transparent = matches!(server_config.protocol, ServerProxyConfig::Redirect { .. } | ServerProxyConfig::Tproxy { .. });
    if transparent {
        if !cfg!(target_os = "linux") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{} inbounds need Linux (SO_ORIGINAL_DST / IP_TRANSPARENT)", server_config.protocol),
            ));
        }
        if let BindLocation::Address(addresses) = &server_config.bind_location {
            for address in addresses.iter() {
                let loopback = address.to_socket_addrs().map(|v| v.iter().all(|a| a.ip().is_loopback())).unwrap_or(false);
                if !loopback {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("{} must bind loopback; {address} is reachable from other hosts", server_config.protocol),
                    ));
                }
            }
        }
        let is_tproxy = matches!(server_config.protocol, ServerProxyConfig::Tproxy { .. });
        if is_tproxy != (server_config.transport == Transport::Udp) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tproxy is the only protocol on `transport: udp`, and needs it",
            ));
        }
        if let ServerProxyConfig::Tproxy { udp_nat_max, udp_timeout } = &server_config.protocol {
            if *udp_nat_max == 0 || *udp_timeout == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "tproxy udp_timeout and udp_nat_max must be positive"));
            }
        }
    }
```

Also the existing `if server_config.transport != Transport::Tcp && server_config.tcp_settings.is_some()` stays. Add config-level tests: `redirect` on `0.0.0.0` refused, `tproxy` without `transport: udp` refused, `redirect` with `transport: udp` refused, both accepted on loopback (the acceptance test gated `#[cfg(target_os = "linux")]`, the refusals unconditional).

`src/tcp/tcp_server_handler_factory.rs`: `ServerProxyConfig::Redirect {} => Box::new(crate::redirect_handler::RedirectServerHandler::new(client_proxy_selector.clone())),` and `ServerProxyConfig::Tproxy { .. } => unreachable!("tproxy runs on the UDP transport, not through the TCP handler factory"),`.

`src/tcp/tcp_server.rs::inbound_label` (Clash plan Task 3, if landed): `P::Redirect { .. } => "redirect"`, `P::Tproxy { .. } => "tproxy"`.

- [ ] **Step 5: The root-gated netfilter test**

`tests/transparent.rs`:

```rust
//! The transparent inbounds under real netfilter rules. Root only; run with
//! `sudo -E cargo test --test transparent -- --ignored`. Linux only.
#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn sh(cmd: &str) {
    let status = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    assert!(status.success(), "{cmd}");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn wait_for(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() { return; }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{addr} never came up");
}

#[tokio::test]
#[ignore]
async fn redirect_forwards_to_the_original_destination() {
    assert!(is_root(), "needs root for iptables");
    let listener_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(&config, format!("- address: 127.0.0.1:{listener_port}\n  protocol:\n    type: redirect\n")).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("--no-reload").arg(&config).kill_on_drop(true)
        .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
    wait_for(format!("127.0.0.1:{listener_port}").parse().unwrap()).await;

    // An echo target on a port the rule below redirects away from.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(b"echo:").await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    // The client's own OUTPUT hook: same shape awg-manager installs in PREROUTING for the LAN.
    let rule = format!("OUTPUT -t nat -p tcp -d 127.0.0.1 --dport {target_port} -j REDIRECT --to-ports {listener_port}");
    sh(&format!("iptables -A {rule}"));
    let result = async {
        let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{target_port}")).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 10];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"echo:hello");
    };
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), result).await;
    sh(&format!("iptables -D {rule}"));
    child.kill().await.unwrap();
    outcome.expect("the redirected connection reached the target through shoes");
}
```

The redirect rule targets the *client's* connection, so the client connects to `target_port`, the kernel diverts it to shoes, and shoes must dial `target_port` itself without being redirected again: the `REDIRECT` rule matches by `--dport` on the original destination, and shoes' outbound connection to the same port would match too. Exclude shoes' own uid: run the test with the rule `-m owner ! --uid-owner 0` if the binary runs as root, or simpler, have shoes dial an address the rule does not match: bind the echo target on `127.0.0.2:<port>` and write the rule for `-d 127.0.0.1`; shoes dials the original destination `127.0.0.1:<port>` which... also matches. Use the owner match: `-m owner ! --uid-owner $(id -u nobody)` and run the shoes child as `nobody` via `Command::uid`. Adjust the test accordingly: spawn with `.uid(65534)`; the loop guard in `RedirectServerHandler` is what this test proves does not fire.

- [ ] **Step 6: Run, gates, commit**

```bash
cargo test --locked original_destination redirect validate
cargo clippy --locked --bins --tests -- -D warnings
# on a Linux box or CI: sudo -E cargo test --locked --test transparent -- --ignored
git add src/async_stream.rs src/redirect_handler.rs src/tproxy src/config src/tcp src/lib.rs src/main.rs tests/transparent.rs
git -c user.email=ayastrebov@gmail.com commit -m "redirect inbound: forward a NAT-redirected connection to its original destination"
```

---

### Task 3: Per-listener UDP router limits

Spec: "Slice 2" → "`tproxy`" (`udp_timeout`, `udp_nat_max`).

**Files:**
- Modify: `src/routing/udp_router.rs:40, 234, 953, 992, 1322-1331`, `UdpRouter::new`

**Interfaces:**
- Produces: `pub struct RouterLimits { pub session_timeout: Duration, pub max_sessions: usize }` with `Default` = today's constants (200 s, unbounded → `usize::MAX`); `run_udp_routing_with_limits(server, selector, resolver, need_initial_flush, limits)`; `run_udp_routing` unchanged, delegating with `RouterLimits::default()`.

- [ ] **Step 1: Failing test**

In `udp_router.rs` tests, using whatever fake targeted stream the module's tests already build (there is a test harness around line 1400; reuse its stream type):

```rust
    #[tokio::test]
    async fn the_session_cap_refuses_a_new_destination_and_expiry_frees_it() {
        let limits = RouterLimits { session_timeout: Duration::from_millis(200), max_sessions: 1 };
        // Two datagrams to two destinations: the second must not create a
        // session while the first is live, and must after it expires.
        // Assert through the router's session count between polls.
        ...
    }
```

Write it against the existing harness's shape: feed a datagram to destination A, poll, assert `sessions.len() == 1`; feed one to B, poll, assert still 1 and that B's datagram was dropped with a `warn!`; advance time past 200 ms (`tokio::time::pause()` + `advance`), poll, assert 0; feed B, poll, assert 1.

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --locked udp_router::tests::the_session_cap`
Expected: FAIL to compile (`RouterLimits`).

- [ ] **Step 3: Implement**

```rust
/// Per-listener session policy. The defaults are what every UDP inbound had
/// before `tproxy` made them configurable.
#[derive(Debug, Clone, Copy)]
pub struct RouterLimits {
    pub session_timeout: Duration,
    pub max_sessions: usize,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self { session_timeout: Duration::from_secs(SESSION_TIMEOUT_SECS), max_sessions: usize::MAX }
    }
}
```

`UdpRouter` gains `limits: RouterLimits`; `new` gains the parameter; the two `Duration::from_secs(SESSION_TIMEOUT_SECS)` sites use `self.limits.session_timeout` (thread it into `RoutingSession::reset_expiry` as an argument). Before a new session is created (the `pending_creates` push, around the lookup insert at `:940`), add:

```rust
                if self.sessions.len() + self.pending_creates.len() >= self.limits.max_sessions {
                    warn!("UDP session cap {} reached; dropping datagram to {destination}", self.limits.max_sessions);
                    continue; // or the equivalent early return in that branch
                }
```

`run_udp_routing_with_limits` is `run_udp_routing` with the extra argument; `run_udp_routing` calls it with `RouterLimits::default()`. Export both and `RouterLimits` from `src/routing/mod.rs`.

- [ ] **Step 4: Run, commit**

```bash
cargo test --locked udp_router
git add src/routing/udp_router.rs
git -c user.email=ayastrebov@gmail.com commit -m "udp router: per-listener session timeout and cap"
```

---

### Task 4: The `tproxy` UDP inbound

Spec: "Slice 2" → "`tproxy`".

**Files:**
- Modify: `src/tproxy/mod.rs`
- Modify: `src/tcp/tcp_server.rs:394` (`Transport::Udp` arm), `src/socket_util.rs` (transparent bind helper)
- Modify: `tests/transparent.rs` (second test)

**Interfaces:**
- Consumes: Task 2 `sys::{make_transparent, recv_with_original_destination}`; Task 3 `run_udp_routing_with_limits`, `RouterLimits`.
- Produces: `pub async fn start_tproxy_udp_server(config: ServerConfig, resolver: Arc<dyn Resolver>) -> io::Result<Vec<JoinHandle<()>>>`; `struct TproxyClientStream` implementing `AsyncTargetedMessageStream`.

- [ ] **Step 1: Failing unit test**

In `src/tproxy/mod.rs` tests (Linux only, no root needed: it tests the demux and the stream, not the kernel):

```rust
    #[tokio::test]
    async fn datagrams_are_demultiplexed_by_client_and_carry_their_destination() {
        let (tx, mut stream) = TproxyClientStream::new_for_test("10.0.0.5:4000".parse().unwrap());
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        tx.send((dst, b"query".to_vec().into_boxed_slice())).await.unwrap();
        let mut buf = [0u8; 64];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        let target = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut rb)).await.unwrap();
        assert_eq!(target.to_socket_addr_nonblocking(), Some(dst));
        assert_eq!(rb.filled(), b"query");
    }
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --locked tproxy`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

`src/socket_util.rs`, Linux only:

```rust
/// A UDP listener for transparent proxying: `IP_TRANSPARENT` so it receives
/// datagrams the policy route delivered for other addresses, and
/// `IP_RECVORIGDSTADDR` so each read reports where the datagram was going.
#[cfg(target_os = "linux")]
pub fn new_transparent_udp_listener(bind: SocketAddr) -> std::io::Result<socket2::Socket> {
    use std::os::fd::AsRawFd;
    let socket = new_socket2_udp_socket_with_buffer_size(bind.is_ipv6(), None, None, false, Some(1 << 20))?;
    crate::tproxy::sys::make_transparent(socket.as_raw_fd(), bind.is_ipv6(), true)?;
    socket.bind(&socket2::SockAddr::from(bind))?;
    Ok(socket)
}

/// A reply socket that appears to be `spoof`: bound to it with
/// `IP_TRANSPARENT`, so the client sees the remote it spoke to.
#[cfg(target_os = "linux")]
pub fn new_transparent_reply_socket(spoof: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let socket = new_socket2_udp_socket(spoof.is_ipv6(), None, None, true)?;
    crate::tproxy::sys::make_transparent(socket.as_raw_fd(), spoof.is_ipv6(), false)?;
    socket.bind(&socket2::SockAddr::from(spoof))?;
    into_tokio_udp_socket(socket)
}
```

`reuse_port: true` on the reply socket: two clients talking to the same remote need two sockets bound to the same spoofed address.

`src/tproxy/mod.rs`:

```rust
//! The `tproxy` UDP inbound. See docs/specs/2026-09-11-awg-manager-engine.md.
//!
//! One transparent listener; a demux task reads it and hands each datagram
//! to the stream for its client address, creating a client on first sight.
//! Each client runs the existing per-destination `UdpRouter`, so routing,
//! sessions and expiry are the code every other UDP inbound uses. Replies
//! go out through a per-client cache of sockets bound transparently to the
//! remote's address.

pub mod sys;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use lru::LruCache;
    use tokio::io::ReadBuf;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use crate::address::NetLocation;
    use crate::async_stream::{AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncTargetedMessageStream, AsyncWriteSourcedMessage};
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::config::{BindLocation, ServerConfig, ServerProxyConfig};
    use crate::resolver::Resolver;
    use crate::routing::{RouterLimits, ServerStream, run_udp_routing_with_limits};

    const REPLY_SOCKETS_PER_CLIENT: usize = 64;
    const CLIENT_QUEUE: usize = 256;

    type Datagram = (SocketAddr, Box<[u8]>); // (original destination, payload)

    /// One LAN client's view of the listener: reads are the datagrams the
    /// demux task delivered for it; writes are replies to it, spoofed.
    pub struct TproxyClientStream {
        client: SocketAddr,
        rx: mpsc::Receiver<Datagram>,
        replies: LruCache<SocketAddr, Arc<tokio::net::UdpSocket>>,
    }

    impl TproxyClientStream {
        fn new(client: SocketAddr, rx: mpsc::Receiver<Datagram>) -> Self {
            Self { client, rx, replies: LruCache::new(std::num::NonZeroUsize::new(REPLY_SOCKETS_PER_CLIENT).unwrap()) }
        }

        #[cfg(test)]
        pub fn new_for_test(client: SocketAddr) -> (mpsc::Sender<Datagram>, Self) {
            let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
            (tx, Self::new(client, rx))
        }

        fn reply_socket(&mut self, spoof: SocketAddr) -> std::io::Result<Arc<tokio::net::UdpSocket>> {
            if let Some(s) = self.replies.get(&spoof) {
                return Ok(s.clone());
            }
            let s = Arc::new(crate::socket_util::new_transparent_reply_socket(spoof)?);
            self.replies.put(spoof, s.clone());
            Ok(s)
        }
    }

    impl AsyncReadTargetedMessage for TproxyClientStream {
        fn poll_read_targeted_message(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<NetLocation>> {
            let this = self.get_mut();
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some((destination, payload))) => {
                    let n = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..n]);
                    Poll::Ready(Ok(NetLocation::from(destination)))
                }
                Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "client expired"))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWriteSourcedMessage for TproxyClientStream {
        fn poll_write_sourced_message(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8], source: &SocketAddr) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let socket = match this.reply_socket(*source) {
                Ok(s) => s,
                Err(e) => return Poll::Ready(Err(e)),
            };
            match socket.poll_send_to(cx, buf, this.client) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncFlushMessage for TproxyClientStream {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
    }
    impl AsyncShutdownMessage for TproxyClientStream {
        fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
    }
    impl AsyncPing for TproxyClientStream {
        fn supports_ping(&self) -> bool { false }
        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> { Poll::Ready(Ok(false)) }
    }
    impl AsyncTargetedMessageStream for TproxyClientStream {}

    struct Client {
        tx: mpsc::Sender<Datagram>,
        last_seen: tokio::time::Instant,
        task: JoinHandle<()>,
    }

    /// The listener: bind, then the demux loop.
    pub async fn start_tproxy_udp_server(config: ServerConfig, resolver: Arc<dyn Resolver>) -> std::io::Result<Vec<JoinHandle<()>>> {
        let ServerProxyConfig::Tproxy { udp_timeout, udp_nat_max } = config.protocol else {
            unreachable!("validated: transport udp is tproxy");
        };
        let rules = config.rules.map(crate::config::ConfigSelection::unwrap_config).into_vec();
        let selector = Arc::new(crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(rules, resolver.clone()));
        let BindLocation::Address(addresses) = config.bind_location else {
            return Err(std::io::Error::other("tproxy needs an address bind"));
        };
        let mut handles = Vec::new();
        for address in addresses.into_vec() {
            for bind in address.to_socket_addrs()? {
                println!("Starting TPROXY UDP server at {bind}");
                let socket = crate::socket_util::new_transparent_udp_listener(bind)?;
                let fd = AsyncFd::new(socket)?;
                let limits = RouterLimits { session_timeout: Duration::from_secs(udp_timeout), max_sessions: udp_nat_max };
                handles.push(tokio::spawn(demux(fd, selector.clone(), resolver.clone(), limits)));
            }
        }
        Ok(handles)
    }

    async fn demux(fd: AsyncFd<socket2::Socket>, selector: Arc<ClientProxySelector>, resolver: Arc<dyn Resolver>, limits: RouterLimits) {
        let mut clients: HashMap<SocketAddr, Client> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        let per_client = RouterLimits { session_timeout: limits.session_timeout, max_sessions: limits.max_sessions };
        loop {
            tokio::select! {
                readable = fd.readable() => {
                    let mut guard = match readable { Ok(g) => g, Err(e) => { log::error!("tproxy listener: {e}"); return; } };
                    let result = guard.try_io(|inner| sys::recv_with_original_destination(inner.get_ref().as_raw_fd(), &mut buf));
                    let (n, source, destination) = match result {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => { log::debug!("tproxy recvmsg: {e}"); continue; }
                        Err(_would_block) => continue,
                    };
                    let Some(destination) = destination else {
                        log::debug!("tproxy: datagram from {source} without an original destination; dropped");
                        continue;
                    };
                    let live_sessions: usize = clients.len();
                    let client = match clients.get_mut(&source) {
                        Some(c) => c,
                        None => {
                            if live_sessions >= limits.max_sessions {
                                log::warn!("tproxy: udp_nat_max {} clients reached; dropping {source}", limits.max_sessions);
                                continue;
                            }
                            let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
                            let stream = TproxyClientStream::new(source, rx);
                            let selector = selector.clone();
                            let resolver = resolver.clone();
                            let task = tokio::spawn(async move {
                                let _handle = crate::connection_registry::register(source, "tproxy", crate::connection_registry::Network::Udp);
                                if let Err(e) = run_udp_routing_with_limits(ServerStream::Targeted(Box::new(stream)), selector, resolver, false, per_client).await {
                                    log::debug!("tproxy client {source} ended: {e}");
                                }
                            });
                            clients.insert(source, Client { tx, last_seen: tokio::time::Instant::now(), task });
                            clients.get_mut(&source).unwrap()
                        }
                    };
                    client.last_seen = tokio::time::Instant::now();
                    if client.tx.try_send((destination, buf[..n].to_vec().into_boxed_slice())).is_err() {
                        log::debug!("tproxy: client {source} queue full; datagram dropped");
                    }
                }
                _ = sweep.tick() => {
                    let now = tokio::time::Instant::now();
                    clients.retain(|source, c| {
                        let keep = now.duration_since(c.last_seen) < limits.session_timeout && !c.task.is_finished();
                        if !keep { log::debug!("tproxy: client {source} expired"); c.task.abort(); }
                        keep
                    });
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
```

The `connection_registry::register` line exists only if the Clash plan's Task 2 has landed; otherwise omit it and let that plan's Task 3 add it. `src/routing/mod.rs:10` exports only `ServerStream` and `run_udp_routing`; extend it to `pub use udp_router::{RouterLimits, ServerStream, run_udp_routing, run_udp_routing_with_limits};` (Task 3 should already have done this; verify).

`src/tcp/tcp_server.rs:394`:

```rust
        Transport::Udp => {
            #[cfg(target_os = "linux")]
            match crate::tproxy::start_tproxy_udp_server(config.clone(), resolver).await {
                Ok(handles) => join_handles.extend(handles),
                Err(e) => return Err(e),
            }
            #[cfg(not(target_os = "linux"))]
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "transport: udp is Linux-only (tproxy)"));
        }
```

- [ ] **Step 4: The root-gated test**

Append to `tests/transparent.rs`:

```rust
#[tokio::test]
#[ignore]
async fn tproxy_delivers_a_datagram_and_spoofs_the_reply_source() {
    assert!(is_root(), "needs root for iptables and IP_TRANSPARENT");
    let listener_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(&config, format!("- address: 127.0.0.1:{listener_port}\n  transport: udp\n  protocol:\n    type: tproxy\n")).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("--no-reload").arg(&config).kill_on_drop(true)
        .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // A UDP echo on a second loopback address, so the client's datagram to it
    // is what the TPROXY rule diverts, and shoes' own dial to it is not.
    let echo = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        let (n, from) = echo.recv_from(&mut b).await.unwrap();
        echo.send_to(&b[..n], from).await.unwrap();
    });
    // Client datagrams are locally generated, so they traverse OUTPUT, not
    // PREROUTING; mark them there and let the policy route loop them back
    // to PREROUTING, where TPROXY can act. This is the local-client shape
    // of the rules awg-manager installs for LAN clients.
    let setup = [
        "ip rule add fwmark 0x1 lookup 100 priority 30000".to_string(),
        "ip route add local 0.0.0.0/0 dev lo table 100".to_string(),
        format!("iptables -t mangle -A OUTPUT -p udp -d 127.0.0.2 --dport {} -m owner ! --uid-owner 65534 -j MARK --set-mark 0x1", echo_addr.port()),
        format!("iptables -t mangle -A PREROUTING -p udp -d 127.0.0.2 --dport {} -j TPROXY --on-port {listener_port} --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1", echo_addr.port()),
    ];
    for s in &setup { sh(s); }
    let result = async {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", echo_addr).await.unwrap();
        let mut b = [0u8; 64];
        let (n, from) = client.recv_from(&mut b).await.unwrap();
        assert_eq!(&b[..n], b"ping");
        assert_eq!(from, echo_addr, "the reply must appear to come from the echo, not from shoes");
    };
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), result).await;
    for s in setup.iter().rev() {
        let _ = Command::new("sh").arg("-c").arg(s.replace(" -A ", " -D ").replace("rule add", "rule del").replace("route add", "route del")).status();
    }
    child.kill().await.unwrap();
    outcome.expect("the datagram went through shoes and came back spoofed");
}
```

Run the shoes child as uid 65534 (`.uid(65534)` on the command) so the owner match excludes its own outbound datagrams, and grant it `CAP_NET_ADMIN` with `setcap cap_net_admin+ep` on the test binary's copy of `shoes` before spawning (the test does `sh("setcap cap_net_admin+ep <path>")` on a copy in the temp dir and runs that copy). The exact loopback-marking recipe may need one iteration on the CI kernel; that is what the ignored gate is for.

- [ ] **Step 5: Run, gates, commit**

```bash
cargo test --locked tproxy
cargo clippy --locked --bins --tests -- -D warnings
cargo build --locked --features control-stats
# Linux, root: sudo -E cargo test --locked --test transparent -- --ignored
git add src/tproxy src/socket_util.rs src/tcp/tcp_server.rs src/routing tests/transparent.rs
git -c user.email=ayastrebov@gmail.com commit -m "tproxy inbound: transparent UDP with per-client routing and spoofed replies"
```

---

### Task 5: CI, docs, and the router run

**Files:**
- Modify: `.github/workflows/test.yml`, `README.md`, this plan.

- [ ] **Step 1: CI step**

In `test.yml` after the desktop step, Linux only:

```yaml
      # The transparent inbounds under real netfilter rules. Root on the
      # runner is what makes iptables and IP_TRANSPARENT available.
      - name: Transparent inbound tests (root)
        if: runner.os == 'Linux'
        run: sudo -E env "PATH=$PATH" cargo test --locked --test transparent -- --ignored
```

- [ ] **Step 2: README**

Under "Supported Protocols" add a "Transparent proxy (Linux)" subsection with the two YAML blocks from the spec and the sentence that the kernel plumbing is the host's, with the `ip rule` / `ip route local` / `TPROXY` lines the test uses as the reference recipe.

- [ ] **Step 3: The router run**

On a Keenetic aarch64 with awg-manager pointed at shoes for the tproxy router mode (awg-manager's emitter is its own work): all three of its health probes green (`/proc/net/tcp` LISTEN on 51272, `/proc/net/udp` bound on 51271, Clash `/version` once the Clash plan's slice 1 has landed), a browser on a LAN client reaching a site through it, a DNS lookup from the LAN client, and the RSS table from the spec repeated on the router. Record the figures here:

```
Keenetic model: ____   idle RSS: ____ MB   after 1 GB download: ____ MB   fork idle: ____ MB
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/test.yml README.md docs/plans/2026-09-11-awg-manager-engine.md
git -c user.email=ayastrebov@gmail.com commit -m "ci+docs: transparent inbound tests under root; README section"
```

---

## Slices 3 to 6

Each is planned when the slice before it has run under awg-manager on a router, because each one's shape depends on what that run found:

- **Slice 3, rules** (`all_of`/`any_of`, `source_masks`, per-rule `udp_timeout`, the `.srs` encoder and `rule-set compile`/`match`): after slice 2's router run shows which rule shapes awg-manager's presets actually emit against shoes.
- **Slice 4, DNS rules**: after slice 3, because a `dns_rules` mask is a slice-3 mask.
- **Slice 5, Chrome ClientHello**: only if the Reality link opened during the first router run is reset where the fork's is not.
- **Slice 6, MIPS**: last, by the user's instruction; a toolchain task with its own plan.
