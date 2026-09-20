# awg-manager engine, slices 1 and 2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The process contract awg-manager holds its engine to (`SIGHUP`, `check`, `version`), and the two transparent-proxy inbounds its tproxy router mode is built on (`redirect` for TCP, `tproxy` for UDP), on Linux.

**Architecture:** `redirect` reads `SO_ORIGINAL_DST` through a new default method on `AsyncStream` implemented for `TcpStream`, and is otherwise a `PortForwardServerHandler` whose target comes from the socket. `tproxy` is the first `Transport::Udp` server: one `IP_TRANSPARENT` listener with `IP_RECVORIGDSTADDR`, demultiplexed by client address into one `UdpRouter` per client over an `AsyncTargetedMessageStream`, replies spoofed through a per-client cache of transparent sockets. Both register at the accept edge like every other inbound.

**Tech Stack:** Rust 2024, tokio (`AsyncFd`), `socket2`, `libc` (all existing deps), the existing `UdpRouter`.

**Spec:** `docs/specs/2026-09-11-awg-manager-engine.md`, slices 1 and 2. The Clash API plan (`docs/plans/2026-09-09-clash-api.md`) is independent; where a task here touches the connection registry it says so, and the touch is the same call the other inbounds make.

## Status, 2026-09-20

Reviewed against `mobile` at `89aebfa`. What has merged since this was written, and what each changes here:

| Merged | What it settles for this plan |
|---|---|
| #23 engine contract (`d986808`) | Task 1 is done. Slice 1 is complete. |
| #22 Clash API slice 1 (`a85cda6`) | The connection registry exists, so every "if landed" below is now "call it". `register` and `counted` compile to no-ops without `control-connections`, so the calls are unconditional. `/version` answers, which is awg-manager's third health probe. |
| #24 Keenetic builds (`89aebfa`) | Slice 6 ran out of order and mostly succeeded: `scripts/build-keenetic.sh` produces aarch64 and mipsel binaries. What is left of it is listed under "Slices 3 to 6". The router run in Task 5 has a binary to use. |
| #25 TUN fast path (`4e0df5e`) | Nothing here; it matters to the two tun modes, which need no engine work. |

**The first router run is unblocked and does not wait for slice 2.** The spec's order of work puts it after slice 1: the legacy-tunnel mode needs only a `mixed` inbound, `SIGHUP`, `check`, `version` and Clash `/version`, all of which are on `mobile`, and an aarch64 binary, which the build script produces. It is gated on the awg-manager emitter, which is that repository's work. It is also slice 5's gate and the first real RSS figure, so it is worth more than its size suggests. Tasks 2 to 4 can proceed in parallel with it.

Corrections made in this review, each marked **(review)** where it lands:

- **`udp_nat_max` was not enforced.** Task 4's demux capped *clients* at `udp_nat_max` and then gave *each* client a router capped at the same figure, so the listener's bound was the square of what the constraint below promises. One shared budget now spans the listener.
- **The reply-socket total was unbounded**, 64 per client with no cap on the sum. Same fix, second budget. The spec's `RLIMIT_NOFILE` raise was in no task; it is in Task 4 now.
- **Task 2 would have failed the gate.** It put `make_transparent` and `recv_with_original_destination` in `tproxy::sys` two tasks before anything calls them; `mod tproxy` is declared in `src/main.rs`, so `--bins -D warnings` rejects them as dead code (AGENTS.md, "Traps"). They move to Task 4, where their caller is.
- **Local copies of kernel constants are dropped.** libc 0.2.189, the locked version, exports all six (`SO_ORIGINAL_DST`, `IP6T_SO_ORIGINAL_DST`, `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`, `IPV6_TRANSPARENT`, `IPV6_RECVORIGDSTADDR`) with the values the plan had typed out. A second copy can only drift.
- **The netfilter tests used `tokio::process`**, which Task 1 found is not enabled in this crate. They use `std::process` with the kill-on-drop guard from `tests/process_contract.rs`.
- **The redirect test's loop-avoidance recipe was left as thinking-out-loud.** It is one definite recipe now.
- **Task 5 missed the documentation rule**: `CONFIG.md`, an `examples/` config and the release smoke loop (AGENTS.md, "Every option reaches the documentation and an example").
- Gates, environment and commit conventions now follow AGENTS.md; the development host is Linux, so the root-gated tests run locally and not only in CI.

## Global Constraints

- **Linux only for the two inbounds.** `redirect` and `tproxy` are refused at validation on every other OS with a message naming Linux; every `libc` call sits under `#[cfg(target_os = "linux")]`, and the config types exist everywhere so a config parses the same on a Mac.
- **Loopback only, for `tproxy`** (spec, "Security notes"): a `tproxy` bind on a non-loopback address is a validation error. `redirect` was under the same rule until Task 2 found it cannot be: `REDIRECT` delivers to the LAN interface's address, so awg-manager's own `redirect-in` listens on `0.0.0.0`. A direct connection is refused instead.
- **No debounce on `SIGHUP`** (spec, "Slice 1"); `--no-reload` does not disable it.
- **`udp_nat_max` bounds file descriptors**: sessions across all clients of a `tproxy` listener never exceed it, and neither do reply sockets. Both are enforced by a budget shared across the listener's clients (Tasks 3 and 4), not by a per-client figure. **(review)**
- **Registry**: both inbounds call `connection_registry::register` / `counted` at the accept edge with a label from `tcp_server::inbound_label`, exactly as `src/tcp/tcp_server.rs` does for the others. Unconditional: the no-feature build gets the no-op versions.
- **Packet path** (AGENTS.md, "Packet paths"): the `tproxy` demux runs once per datagram. No task per datagram, every queue bounded with a comment saying that a full one drops, and no fresh `Vec` per datagram where a shared buffer does the job (Task 4 says how).
- **Gates for every task** are AGENTS.md's verification gate, in full. Add `cargo test --locked --features clash-api` whenever a task touches the registry or `inbound_label`, because those arms only compile there. The FFI clippy pair is needed only if a task strays into `src/config/mod.rs` or `src/socket_protector.rs`; `src/socket_util.rs` alone does not need it. The netfilter tests are `sudo -E env "PATH=$PATH" cargo test --locked --test transparent -- --ignored`, on the development host as well as in CI.
- **Commits** follow AGENTS.md: `area: imperative summary`, the why in the body, the co-author trailer, and the same command again if signing fails with `failed to fill whole buffer`.

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
- `src/connection_registry.rs` — `CountingStream` forwards `original_destination` (its `impl AsyncStream` is empty today).
- `src/config/types/server.rs` — `Redirect`, `Tproxy` variants, `Display`.
- `src/config/validate.rs` — OS and bind rules for both; `transport: udp` only with `tproxy`.
- `src/tcp/tcp_server_handler_factory.rs` — `Redirect` arm.
- `src/tcp/tcp_server.rs` — `Transport::Udp` arm.
- `src/routing/udp_router.rs`, `src/routing/mod.rs` — `RouterLimits`, `run_udp_routing_with_limits`, the re-export.
- `src/lib.rs`, `src/main.rs` — module declarations.
- `README.md`, `CONFIG.md` — a section for the two inbounds; every field and its default.
- `examples/transparent_proxy.yaml` — both inbounds, cert-free.
- `.github/workflows/test.yml` — the root-gated Linux step.
- `.github/workflows/build.yml` — the example joins the Linux arm of the `Smoke test binary` loop (validation refuses it elsewhere).
- `ROADMAP.md` — the awg-manager engine work and what is left of it.

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

**Status:** done on `feature/redirect-inbound`. What was built differs from the steps below in five places, and the code is the reference where they disagree:

1. **`Some` from `SO_ORIGINAL_DST` does not mean redirected.** Step 1's first test failed on the development host for a reason the plan had not imagined: with conntrack loaded, a connection dialled straight at the listener reports the listener's own address, so the handler's `None` check never fired and a direct connection made shoes dial itself without end. `AsyncStream for TcpStream` now compares the answer with the local address (canonical forms) and reports `None` when they match. `tests/transparent.rs` has a rootless test for it that hangs and fails without the comparison.
2. **No loopback rule.** `REDIRECT` in `PREROUTING` rewrites the destination to the inbound interface's address, not `127.0.0.1`; awg-manager binds its sing-box `redirect-in` to `0.0.0.0` for that reason (`internal/singbox/router/service_lifecycle.go`). Validation accepts any IP; item 1 is what makes that safe.
3. **Only the `Redirect` variant was added.** `Tproxy` waits for Task 4: adding it now would make validation accept a config that then hits `todo!()` in `start_tcp_or_quic_servers`. Task 4 adds the variant, its validation and its `unreachable!` factory arm together.
4. **`redirect` nested in TLS or WebSocket is refused**, which the plan did not cover: the handler would be handed a wrapper with no socket to ask.
5. **`inbound_label` needed no arm.** Its fallback lowercases `Display`, which gives `redirect@…`. `OutboundCountingStream` got no forward either: it wraps outbound streams, which no `redirect` handler ever sees.

The root-gated test runs in CI (`Transparent inbound tests (root)` in `test.yml`); it is built unprivileged and run under `sudo` so `target/` stays the runner's. It was not run on the development host, where `sudo` needs a password.

**Files:**
- Modify: `src/async_stream.rs` — the `AsyncStream` trait and its impls for `TcpStream`, `PermitStream`, `Box<T>`, `&mut T` (`:173, 235, 313, 528-529` at `89aebfa`)
- Modify: `src/connection_registry.rs:160` (forward the method on `CountingStream`). This one is not optional: the accept loop wraps every stream in `counted` before the handler sees it, so without the forward a `redirect` listener refuses every connection in a `clash-api` build and works in a default one.
- Create: `src/redirect_handler.rs`
- Modify: `src/config/types/server.rs` (`ServerProxyConfig` variant, `Display`), `src/config/validate.rs` (`validate_server_config`), `src/tcp/tcp_server_handler_factory.rs`, `src/tcp/tcp_server.rs` (`inbound_label`). Line numbers from the first draft have moved; go by symbol.
- Modify: `src/lib.rs`, `src/main.rs` (`mod redirect_handler;`)
- Create: `tests/transparent.rs` (first test)

**Interfaces:**
- Produces: `AsyncStream::original_destination(&self) -> Option<SocketAddr>` (default `None`); `ServerProxyConfig::Redirect {}`; `RedirectServerHandler::new(proxy_selector)`.

- [x] **Step 1: Failing unit test**

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

- [x] **Step 2: Run, expect failure**

Run: `cargo test --locked original_destination redirect`
Expected: FAIL to compile.

- [x] **Step 3: The trait method and the Linux impl**

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

`PermitStream`, `Box<T>`, `&mut T`, `OutboundCountingStream` and `CountingStream` forward: `fn original_destination(&self) -> Option<SocketAddr> { self.inner.original_destination() }` (`(**self)` for `Box`, `(**self)` for `&mut T`).

**(review)** The `CountingStream` forward gets its own test beside the registry's, because it is the one a default build cannot catch: wrap the `Redirected` double from Step 1 in `connection_registry::counted` and assert the address survives. Prove it can fail by deleting the forward and watching that test, and only that test, go red under `--features clash-api`.

Create `src/tproxy/mod.rs` with `pub mod sys;` for now (Task 4 fills the rest) and `src/tproxy/sys.rs`.

**(review)** Only `original_destination` goes in here in this task. `make_transparent` and `recv_with_original_destination` have no caller until Task 4, and `mod tproxy` is declared in `src/main.rs`, so `cargo clippy --bins -- -D warnings` would reject them as dead code; they are written in Task 4, beside their caller. The constants come from `libc`, which exports every one this module needs at the locked 0.2.189; the kernel headers they mirror are `include/uapi/linux/netfilter_ipv4.h` (`SO_ORIGINAL_DST`) and `include/uapi/linux/netfilter_ipv6/ip6_tables.h` (`IP6T_SO_ORIGINAL_DST`).

```rust
//! The Linux socket calls behind transparent proxying. Every function here
//! is `cfg(target_os = "linux")`; the module exists elsewhere so the paths
//! resolve, and the inbounds are refused at validation there.

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::RawFd;

    pub(super) fn v4(sa: &libc::sockaddr_in) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port)))
    }

    pub(super) fn v6(sa: &libc::sockaddr_in6) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(sa.sin6_addr.s6_addr), u16::from_be(sa.sin6_port), sa.sin6_flowinfo, sa.sin6_scope_id))
    }

    /// `SO_ORIGINAL_DST`: the destination before NAT `REDIRECT`. `None` when
    /// the socket was not redirected (`ENOENT`) or the option is unsupported.
    pub fn original_destination(fd: RawFd) -> Option<SocketAddr> {
        // SAFETY: both structs are plain data the kernel fills; `len` tells it
        // how much room there is, and the family check rejects a short write.
        unsafe {
            let mut sa6: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IPV6, libc::IP6T_SO_ORIGINAL_DST, &mut sa6 as *mut _ as *mut libc::c_void, &mut len) == 0
                && sa6.sin6_family as libc::c_int == libc::AF_INET6
            {
                return Some(v6(&sa6));
            }
            let mut sa4: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IP, libc::SO_ORIGINAL_DST, &mut sa4 as *mut _ as *mut libc::c_void, &mut len) == 0
                && sa4.sin_family as libc::c_int == libc::AF_INET
            {
                return Some(v4(&sa4));
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
```

If `v6` is unused by anything but `original_destination` at this point it is still used, so no allow is needed; if clippy disagrees on some configuration, fold the helper into its one caller rather than adding an allow.

Declare `mod tproxy;` in `src/lib.rs` and `src/main.rs` (unconditionally; the file is empty of code off Linux).

- [x] **Step 4: The handler, the variant, validation, the factory**

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

`NetLocation: From<SocketAddr>` already exists in `src/address.rs` (it arrived with the Clash registry), so `NetLocation::from(destination)` compiles as written. **(review)**

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

`src/tcp/tcp_server.rs::inbound_label`: `P::Redirect { .. } => "redirect".to_string()`, `P::Tproxy { .. } => "tproxy".to_string()`, matching the arms around them. The match is exhaustive, so the build fails until these exist.

- [x] **Step 5: The root-gated netfilter test**

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

const NOBODY: u32 = 65534;

/// Kills the child when the test ends, pass or fail. tokio's `process`
/// feature is not enabled in this crate, so there is no `kill_on_drop`;
/// this is the guard `tests/process_contract.rs` uses.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// shoes as uid 65534, from a copy in `dir`. Two reasons for the uid: the
/// netfilter rules below exclude it with `-m owner`, which is what stops
/// shoes' own dial to the original destination from being diverted back
/// into shoes; and it proves the inbounds need a capability, not root. The
/// copy is because `target/` sits under a home directory `nobody` cannot
/// traverse, and because `setcap` must not touch the build's own binary.
fn spawn_shoes_as_nobody(dir: &std::path::Path, config: &std::path::Path, net_admin: bool) -> Child {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    let bin = dir.join("shoes");
    std::fs::copy(env!("CARGO_BIN_EXE_shoes"), &bin).unwrap();
    for (path, mode) in [(dir, 0o755), (bin.as_path(), 0o755), (config, 0o644)] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    if net_admin {
        sh(&format!("setcap cap_net_admin+ep {}", bin.display()));
    }
    Child(
        Command::new(&bin).arg("--no-reload").arg(config).uid(NOBODY).gid(NOBODY)
            .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap(),
    )
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
    let _child = spawn_shoes_as_nobody(dir.path(), &config, false);
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
    // `! --uid-owner`: shoes dials the same address and port the client did.
    // Without the exclusion that dial matches this rule too and loops.
    let rule = format!("OUTPUT -t nat -p tcp -d 127.0.0.1 --dport {target_port} -m owner ! --uid-owner {NOBODY} -j REDIRECT --to-ports {listener_port}");
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
    outcome.expect("the redirected connection reached the target through shoes");
}
```

**(review)** The first draft of this step argued with itself about how to stop shoes' own dial from matching the rule. The answer is the owner match above, with shoes running as `nobody`; nothing else in the step depends on which loopback address the target uses. What the test proves: the client dials `target_port`, the kernel diverts it, shoes reads `SO_ORIGINAL_DST` and dials `target_port` itself, and that second connection is not diverted. If the rule is ever installed without the owner match the test hangs until its five-second timeout rather than passing by accident, because the echo is never reached.

A panic between `iptables -A` and `iptables -D` would leave the rule installed on the development host, which is why the body runs inside `timeout(...)` and the assertion comes after the delete. Keep that order when editing.

- [x] **Step 6: Run, gates, commit**

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
- Modify: `src/routing/udp_router.rs` — `SESSION_TIMEOUT_SECS` and its two uses, `UdpRouter::new`, the session-create path beside `pending_creates`, `run_udp_routing`
- Modify: `src/routing/mod.rs` — the re-export

**Interfaces:**
- Produces: `pub struct RouterLimits { pub session_timeout: Duration, pub max_sessions: usize, pub shared_budget: Option<Arc<Semaphore>> }` with `Default` = today's behaviour (200 s, `usize::MAX`, no budget); `run_udp_routing_with_limits(server, selector, resolver, need_initial_flush, limits)`; `run_udp_routing` unchanged, delegating with `RouterLimits::default()`.

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
#[derive(Debug, Clone)]
pub struct RouterLimits {
    pub session_timeout: Duration,
    /// Sessions this one router may hold.
    pub max_sessions: usize,
    /// Sessions every router sharing this budget may hold between them. A
    /// `tproxy` listener runs one router per LAN client, and its
    /// `udp_nat_max` is a promise about the listener, not about each client.
    pub shared_budget: Option<Arc<tokio::sync::Semaphore>>,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self { session_timeout: Duration::from_secs(SESSION_TIMEOUT_SECS), max_sessions: usize::MAX, shared_budget: None }
    }
}
```

`UdpRouter` gains `limits: RouterLimits`; `new` gains the parameter; the two `Duration::from_secs(SESSION_TIMEOUT_SECS)` sites use `self.limits.session_timeout` (thread it into `RoutingSession::reset_expiry` as an argument). Before a new session is created (the `pending_creates` push), add:

```rust
                if self.sessions.len() + self.pending_creates.len() >= self.limits.max_sessions {
                    warn!("UDP session cap {} reached; dropping datagram to {destination}", self.limits.max_sessions);
                    continue; // or the equivalent early return in that branch
                }
                // The listener-wide budget. The permit lives in the pending
                // create and then in the session, so every way a session can
                // end -- expiry, error, the router being dropped with its
                // client -- returns it without a line of bookkeeping.
                let permit = match &self.limits.shared_budget {
                    Some(budget) => match budget.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            warn!("listener UDP session budget exhausted; dropping datagram to {destination}");
                            continue;
                        }
                    },
                    None => None,
                };
```

**(review)** `shared_budget` is new in this revision. The first draft had only `max_sessions`, and Task 4 handed the same figure to every client's router, so a listener with `udp_nat_max: 4096` could hold 4096 × 4096 sessions. A semaphore rather than an `AtomicUsize` because the release has to happen on every exit path including a dropped router, and an `OwnedSemaphorePermit` in the session does that by construction. `PendingSessionCreate` and `RoutingSession` each gain an `Option<OwnedSemaphorePermit>` field that is never read; name it `_budget_permit` and say why in its comment.

Dropping is the right thing for a full table: it is what a full conntrack table does to a new flow, and the existing flows keep working. Say so in the comment beside the `warn!` (AGENTS.md, "Bound every queue, and decide what a full one does"). The `warn!` fires per dropped datagram, which under a flood is per packet; rate-limit it the way the router's other per-packet warnings are, or log once per crossing.

Extend Step 1's test with the shared case: two routers on one `Semaphore::new(1)`, a datagram to each, the second router creates nothing; drop the first router, feed the second again, it creates its session. Prove it can fail by moving the `try_acquire_owned` after the create and watching the first assertion go red.

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
- Modify: `src/tcp/tcp_server.rs` (the `Transport::Udp => todo!()` arm in `start_tcp_or_quic_servers`, `:483` at `89aebfa`), `src/socket_util.rs` (transparent bind helpers), `src/tproxy/sys.rs`
- Modify: `tests/transparent.rs` (second test)

**Interfaces:**
- Consumes: Task 2 `sys::{v4, v6}`; Task 3 `run_udp_routing_with_limits`, `RouterLimits` and its `shared_budget`.
- Produces also: `sys::{make_transparent, recv_with_original_destination}`, moved here from Task 2 so they land with their caller. **(review)**
- Produces: `pub async fn start_tproxy_udp_server(config: ServerConfig, resolver: Arc<dyn Resolver>) -> io::Result<Vec<JoinHandle<()>>>`; `struct TproxyClientStream` implementing `AsyncTargetedMessageStream`.

- [ ] **Step 1: Failing unit test**

In `src/tproxy/mod.rs` tests (Linux only, no root needed: it tests the demux and the stream, not the kernel):

```rust
    #[tokio::test]
    async fn datagrams_are_demultiplexed_by_client_and_carry_their_destination() {
        let (tx, mut stream) = TproxyClientStream::new_for_test("10.0.0.5:4000".parse().unwrap());
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        tx.send((dst, bytes::Bytes::from_static(b"query"))).await.unwrap();
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

`src/tproxy/sys.rs`, inside `mod linux`, the two calls Task 2 left out. Constants from `libc`; the headers they mirror are `include/uapi/linux/in.h` (`IP_TRANSPARENT` 19, `IP_RECVORIGDSTADDR` 20) and `include/uapi/linux/in6.h` (`IPV6_TRANSPARENT` 75, `IPV6_RECVORIGDSTADDR` 74). These are `SOL_IP`/`SOL_IPV6` options, which unlike `SOL_SOCKET` ones have the same numbers on MIPS, so the mipsel build needs nothing special.

```rust
    fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> std::io::Result<()> {
        // SAFETY: `value` outlives the call and the length is its size.
        let rc = unsafe { libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }

    /// `IP_TRANSPARENT` (needs CAP_NET_ADMIN) and, for a listener,
    /// `IP_RECVORIGDSTADDR` so `recvmsg` reports where each datagram was going.
    /// A failure is returned, never swallowed: a listener without the option
    /// binds fine and then receives nothing, which looks like a dead network.
    pub fn make_transparent(fd: RawFd, ipv6: bool, receive_original_destination: bool) -> std::io::Result<()> {
        let (level, transparent, recv) = if ipv6 {
            (libc::SOL_IPV6, libc::IPV6_TRANSPARENT, libc::IPV6_RECVORIGDSTADDR)
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT, libc::IP_RECVORIGDSTADDR)
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
        // SAFETY: every pointer in `msg` refers to a local that outlives the
        // call; the control buffer is u64-aligned, which cmsghdr requires;
        // CMSG_DATA is cast only after level and type say what it holds.
        unsafe {
            let mut source: libc::sockaddr_storage = std::mem::zeroed();
            let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
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
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                // Reject rather than truncate: a cut datagram forwarded as if
                // whole is worse than a dropped one.
                return Err(std::io::Error::other("datagram larger than the receive buffer"));
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
                if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_RECVORIGDSTADDR {
                    destination = Some(v4(&*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in)));
                } else if hdr.cmsg_level == libc::SOL_IPV6 && hdr.cmsg_type == libc::IPV6_RECVORIGDSTADDR {
                    destination = Some(v6(&*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6)));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            Ok((n as usize, source, destination))
        }
    }
```

`CMSG_DATA` is not guaranteed aligned for `sockaddr_in6` on every architecture; on mipsel an unaligned load traps. Read it with `std::ptr::read_unaligned` rather than the `&*` above if the unit test under QEMU (or a run on the router) faults there. The `recvmsg` parsing is unit-testable without root: a plain UDP socket with `IP_RECVORIGDSTADDR` set (that option needs no capability, only `IP_TRANSPARENT` does) reports its own bound address as the "original" destination, which is enough to prove the control-message walk. Write that test; it is the only coverage this `unsafe` block gets outside the root-gated one.

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

Neither function calls `protect_outbound`, and that is deliberate rather than the omission AGENTS.md warns about: the reply socket's peer is a LAN client, not an upstream, and the socket protector exists only where a VPN service owns the routes (Android, iOS), which is not where `tproxy` compiles. Say so in a comment on `new_transparent_reply_socket`, so the next reader does not "fix" it.

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
    const MAX_DATAGRAM: usize = 65535;

    type Datagram = (SocketAddr, bytes::Bytes); // (original destination, payload)

    /// One LAN client's view of the listener: reads are the datagrams the
    /// demux task delivered for it; writes are replies to it, spoofed.
    pub struct TproxyClientStream {
        client: SocketAddr,
        rx: mpsc::Receiver<Datagram>,
        replies: LruCache<SocketAddr, ReplySocket>,
        /// Reply sockets across every client of this listener.
        reply_budget: Arc<tokio::sync::Semaphore>,
    }

    /// A spoofed socket and its share of the listener's descriptor budget;
    /// evicting it from the LRU returns the permit.
    struct ReplySocket {
        socket: Arc<tokio::net::UdpSocket>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    }

    impl TproxyClientStream {
        fn new(client: SocketAddr, rx: mpsc::Receiver<Datagram>, reply_budget: Arc<tokio::sync::Semaphore>) -> Self {
            Self { client, rx, replies: LruCache::new(std::num::NonZeroUsize::new(REPLY_SOCKETS_PER_CLIENT).unwrap()), reply_budget }
        }

        #[cfg(test)]
        pub fn new_for_test(client: SocketAddr) -> (mpsc::Sender<Datagram>, Self) {
            let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
            (tx, Self::new(client, rx, Arc::new(tokio::sync::Semaphore::new(REPLY_SOCKETS_PER_CLIENT))))
        }

        fn reply_socket(&mut self, spoof: SocketAddr) -> std::io::Result<Arc<tokio::net::UdpSocket>> {
            if let Some(s) = self.replies.get(&spoof) {
                return Ok(s.socket.clone());
            }
            // Out of budget: free this client's own oldest socket and try
            // once more, so a busy client recycles its sockets rather than
            // starving; if the listener is still full the reply is dropped,
            // which for UDP is what a full socket buffer would have done.
            let permit = match self.reply_budget.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    self.replies.pop_lru();
                    self.reply_budget.clone().try_acquire_owned()
                        .map_err(|_| std::io::Error::other("tproxy reply-socket budget exhausted"))?
                }
            };
            let socket = Arc::new(crate::socket_util::new_transparent_reply_socket(spoof)?);
            self.replies.put(spoof, ReplySocket { socket: socket.clone(), _permit: permit });
            Ok(socket)
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
        raise_nofile_limit(udp_nat_max);
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
                // One budget of each kind per listener, shared by every
                // client's router and reply cache: `udp_nat_max` is a promise
                // about the listener's descriptors, not about each client.
                let limits = RouterLimits {
                    session_timeout: Duration::from_secs(udp_timeout),
                    max_sessions: udp_nat_max,
                    shared_budget: Some(Arc::new(tokio::sync::Semaphore::new(udp_nat_max))),
                };
                let reply_budget = Arc::new(tokio::sync::Semaphore::new(udp_nat_max));
                let label = crate::tcp::tcp_server::inbound_label(&config.protocol, &bind.to_string());
                handles.push(tokio::spawn(demux(fd, selector.clone(), resolver.clone(), limits, reply_budget, label)));
            }
        }
        Ok(handles)
    }

    async fn demux(fd: AsyncFd<socket2::Socket>, selector: Arc<ClientProxySelector>, resolver: Arc<dyn Resolver>, limits: RouterLimits, reply_budget: Arc<tokio::sync::Semaphore>, label: &'static str) {
        let mut clients: HashMap<SocketAddr, Client> = HashMap::new();
        // One growing buffer, split per datagram: `split_to(n).freeze()` hands
        // the client task an owned `Bytes` without a fresh allocation per
        // packet; `reserve` allocates a new block only when the last is spent.
        let mut buf = bytes::BytesMut::new();
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                readable = fd.readable() => {
                    let mut guard = match readable { Ok(g) => g, Err(e) => { log::error!("tproxy listener: {e}"); return; } };
                    buf.resize(MAX_DATAGRAM, 0);
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
                            let stream = TproxyClientStream::new(source, rx, reply_budget.clone());
                            let per_client = limits.clone();
                            let selector = selector.clone();
                            let resolver = resolver.clone();
                            let task = tokio::spawn(async move {
                                let _handle = crate::connection_registry::register(source, label, crate::connection_registry::Network::Udp);
                                if let Err(e) = run_udp_routing_with_limits(ServerStream::Targeted(Box::new(stream)), selector, resolver, false, per_client).await {
                                    log::debug!("tproxy client {source} ended: {e}");
                                }
                            });
                            clients.insert(source, Client { tx, last_seen: tokio::time::Instant::now(), task });
                            clients.get_mut(&source).unwrap()
                        }
                    };
                    client.last_seen = tokio::time::Instant::now();
                    // Bounded, and full means drop: the same thing a full socket
                    // buffer does, and the only answer that cannot stall the
                    // listener for every other client.
                    if client.tx.try_send((destination, buf.split_to(n).freeze())).is_err() {
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

**(review)** notes on the listing above.

- `buf.resize(MAX_DATAGRAM, 0)` after a `split_to` re-zeroes 64 KiB per datagram, which is its own per-packet cost. If that shows in a profile, keep a plain `Vec` for `recvmsg` and `copy_from_slice` into a `BytesMut` sized to `n`; either way the rule is one amortised allocation, not one `Vec` per datagram. Pick one, measure, and say which in the comment.
- `inbound_label(&config.protocol, ..)` borrows a field while `config.rules` and `config.bind_location` have been moved out. That compiles, because the moves are of other fields and the two `tproxy` fields are `Copy`; if a later edit makes it stop compiling, borrow the label before the moves rather than cloning the protocol.
- The registry entry is per LAN client, not per UDP session, so its destination stays unset and `/connections` shows one `tproxy@…` row per client. The spec's testing section asked for the original destination there; that holds for `redirect` and is given up for `tproxy`, where a row per destination would mean a registry write on the session-create path. Recorded in the spec's decisions.
- `raise_nofile_limit(udp_nat_max)` is the spec's "RSS budget" paragraph, which no task carried: `getrlimit(RLIMIT_NOFILE)`, raise the soft limit to the hard one, log the figure, and `warn!` if `2 * udp_nat_max + 64` (sessions, reply sockets, and everything else the process holds) exceeds it. It warns rather than refuses because the limit is the host's to change and the listener degrades by dropping, not by failing. Entware's default soft limit is 1024 on some models, below the 4096 default, so this warning is expected on a router and the router run (Task 5) should record what it said.

`src/routing/mod.rs:10` exports only `ServerStream` and `run_udp_routing`; extend it to `pub use udp_router::{RouterLimits, ServerStream, run_udp_routing, run_udp_routing_with_limits};` (Task 3 should already have done this; verify).

`src/tcp/tcp_server.rs`, replacing the `todo!()`:

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
    let _child = spawn_shoes_as_nobody(dir.path(), &config, true);
    wait_for_udp_bound(listener_port).await;

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
    outcome.expect("the datagram went through shoes and came back spoofed");
}
```

`spawn_shoes_as_nobody(.., true)` is Task 2's helper with `setcap cap_net_admin+ep` on the copy, so this test also proves the capability is sufficient and root is not required. **(review)** The first draft slept 500 ms for the listener; `wait_for_udp_bound` polls `/proc/net/udp` for the port instead, which is the probe awg-manager itself uses (spec, "Testing") and costs nothing when the listener is already up:

```rust
async fn wait_for_udp_bound(port: u16) {
    let needle = format!(":{port:04X} ");
    for _ in 0..100 {
        let table = std::fs::read_to_string("/proc/net/udp").unwrap_or_default();
        if table.lines().any(|l| l.split_whitespace().nth(1).is_some_and(|local| format!("{local} ").ends_with(&needle))) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("nothing bound UDP port {port}");
}
```

The exact loopback-marking recipe may need one iteration on the CI kernel; that is what the ignored gate is for. It can be iterated on the development host first, which is Linux.

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
- Modify: `.github/workflows/test.yml`, `.github/workflows/build.yml`, `README.md`, `CONFIG.md`, `ROADMAP.md`, this plan.
- Create: `examples/transparent_proxy.yaml`

- [ ] **Step 1: CI step**

In `test.yml` after the desktop step, Linux only:

```yaml
      # The transparent inbounds under real netfilter rules. Root on the
      # runner is what makes iptables and IP_TRANSPARENT available.
      - name: Transparent inbound tests (root)
        if: runner.os == 'Linux'
        run: sudo -E env "PATH=$PATH" cargo test --locked --test transparent -- --ignored
```

The runner needs `iptables` and `setcap` (`libcap2-bin`); both are on `ubuntu-latest` and `ubuntu-24.04-arm` today, but install them explicitly in the step so an image change fails loudly here rather than as a confusing test error.

- [ ] **Step 2: README, CONFIG.md, the example, the smoke loop**

**(review)** The first draft stopped at the README. AGENTS.md's rule is that every option reaches `CONFIG.md` with its default and `examples/` with a config that parses, and that the example joins the release smoke loop:

- `CONFIG.md`: `redirect` (no fields) and `tproxy` (`udp_timeout`, default 300; `udp_nat_max`, default 4096), both Linux-only and loopback-only, `transport: udp` required for `tproxy` and refused for everything else. Say the things a user learns painfully otherwise: shoes installs no firewall rules or policy routes; `IP_TRANSPARENT` needs `CAP_NET_ADMIN`; a `tproxy` listener without the `ip rule`/`ip route local` pair binds happily and receives nothing; `udp_nat_max` above the descriptor limit is warned about, not refused.
- `examples/transparent_proxy.yaml`: both listeners on awg-manager's ports (`51272` TCP, `51271` UDP) with a direct rule. Cert-free, so it qualifies for the loop.
- `.github/workflows/build.yml`, `Smoke test binary`: add `transparent_proxy` to the **Linux** arm of the `case`, not the common list; validation refuses it on the other two, which is the behaviour, not a failure. A dry run does not bind, so it needs no capability.


Under "Supported Protocols" add a "Transparent proxy (Linux)" subsection with the two YAML blocks from the spec and the sentence that the kernel plumbing is the host's, with the `ip rule` / `ip route local` / `TPROXY` lines the test uses as the reference recipe.

- [ ] **Step 3: The router run**

The binary is `dist/keenetic/` from `scripts/build-keenetic.sh` (PR #24), built with `clash-api` so the third probe has something to answer. On a Keenetic aarch64 with awg-manager pointed at shoes for the tproxy router mode (awg-manager's emitter is its own work): all three of its health probes green (`/proc/net/tcp` LISTEN on 51272, `/proc/net/udp` bound on 51271, Clash `/version` once the Clash plan's slice 1 has landed), a browser on a LAN client reaching a site through it, a DNS lookup from the LAN client, and the RSS table from the spec repeated on the router. Record the figures here:

```
Keenetic model: ____   idle RSS: ____ MB   after 1 GB download: ____ MB   fork idle: ____ MB
RLIMIT_NOFILE the listener reported: ____   udp_nat_max warning shown: yes / no
```

This is the *second* router run. The first one is the legacy-tunnel mode and is unblocked now (see "Status"); if it has happened by the time this step is reached, its RSS figures go in `docs/keenetic-build-2026-09-11.md` under "What is not measured", which is the list they close.

- [ ] **Step 4: ROADMAP**

`ROADMAP.md` has no entry for any of this work. Add one section, "awg-manager engine", pointing at the spec and saying what is deliberately missing after slice 2 and what each gap costs a user: no logical or source rules (awg-manager's rule editor is limited to what `masks` expresses), no DNS rules or port-53 hijack outside TUN (DNS from LAN clients on the tproxy mode bypasses shoes unless the host redirects it), no Chrome ClientHello (unmeasured), no big-endian `mips` build and no shipped MIPS artifact. AGENTS.md: a gap is written down with what it costs to leave.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/test.yml .github/workflows/build.yml README.md CONFIG.md ROADMAP.md examples/transparent_proxy.yaml docs/plans/2026-09-11-awg-manager-engine.md
git -c user.email=ayastrebov@gmail.com commit -m "ci+docs: transparent inbound tests under root; README section"
```

---

## Slices 3 to 6

Each is planned when the slice before it has run under awg-manager on a router, because each one's shape depends on what that run found:

- **Slice 3, rules** (`all_of`/`any_of`, `source_masks`, per-rule `udp_timeout`, the `.srs` encoder and `rule-set compile`/`match`): after slice 2's router run shows which rule shapes awg-manager's presets actually emit against shoes.
- **Slice 4, DNS rules**: after slice 3, because a `dns_rules` mask is a slice-3 mask.
- **Slice 5, Chrome ClientHello**: only if the Reality link opened during the first router run is reset where the fork's is not. That run no longer waits on anything in this repository.
- **Slice 6, MIPS**: was to be last, and ran early as PR #24. Done: a reproducible mipsel build (`scripts/build-keenetic.sh`, `Cross.toml`, `docs/keenetic-build-2026-09-11.md`), jemalloc off and `portable-atomic` in on the target, `version` and `check` passing under QEMU. Left, and still last:
  - `mips-unknown-linux-musl` (big-endian), which awg-manager ships for and nobody has attempted. Same route as mipsel; the endianness is the new risk, in the hand-written codecs rather than the toolchain.
  - A shipped artifact. The build is a script on a developer's machine, not a CI job: it needs nightly `build-std`, a full aws-lc build, and a retry loop around an LLVM MIPS backend that crashes about one build in two. A release-only job is the shape; a per-PR one was declined in #24's review for cost.
  - Anything beyond `version` and `check` on the target. No connection has been carried on MIPS, under QEMU or on a router, and the `portable_atomic` branch of `util::atomic` is compiled there and tested nowhere. Running the counter tests under QEMU user emulation is the cheap first step and needs no router.
  - Slice 2 on MIPS: `CMSG_DATA` alignment in `recv_with_original_destination` (Task 4) is the one place this plan adds code that can behave differently there.
