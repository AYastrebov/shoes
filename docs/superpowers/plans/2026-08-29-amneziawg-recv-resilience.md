# AmneziaWG Receive-Path Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The AmneziaWG receive loop survives transient UDP errors (the `EMSGSIZE` that killed KVN's tunnel), a genuinely dead receive path stops the engine with a reason, and the trailer-probe hint stops blaming `random_trailers` when nothing was received.

**Architecture:** A new process-global `src/fatal.rs` watch channel carries "the engine must die" from the tunnel (which has no handle to the service task) to `control::run_prepared`, which merges it with the host's shutdown signal and turns it into the `Err` that already drives `on_exit` → stopped callback / `last_error`. Inside `src/amneziawg/tunnel.rs`, recv errors are classified (ignore / reset-trailer-window / suspect) and fed to a time-windowed consecutive-error streak; only a socket producing nothing but errors for ~5 s terminates the loop, and that termination reports fatal.

**Tech Stack:** Rust, tokio (`watch`, `oneshot`), existing `awgtun` / `parking_lot` / `libc` dependencies. No new crates. No FFI surface change.

**Spec:** `docs/superpowers/specs/2026-08-29-amneziawg-recv-resilience-design.md`

---

## File map

- Create: `src/fatal.rs` — process-global fatal signal (report / subscribe / reset).
- Modify: `src/lib.rs` — declare `mod fatal;`.
- Modify: `src/main.rs` — declare `#[allow(dead_code)] mod fatal;`.
- Modify: `src/control/mod.rs` — `shutdown_or_fatal` watcher, wired into `run_prepared`.
- Modify: `src/amneziawg/tunnel.rs` — error classification, streak, loop rework, death reporting, `dead` flag, received counter, probe wording.
- Modify: `src/amneziawg/connector.rs` — rebuild a dead tunnel on the next connection.
- Modify: `CHANGELOG.md` — `Unreleased` section.

Run all commands from the repo root (`/home/ayastrebov/VibeProjects/shoes`).

---

### Task 1: `src/fatal.rs` — the process-global fatal signal

**Files:**
- Create: `src/fatal.rs`
- Modify: `src/lib.rs` (module declaration, below `mod amneziawg;` at line 59)
- Modify: `src/main.rs` (module declaration, below `mod dns;` at line 13)

- [ ] **Step 1: Write the module with failing-first tests**

Create `src/fatal.rs`:

```rust
//! A process-global "the engine must die" signal.
//!
//! The AmneziaWG tunnel is created lazily deep inside a connector chain
//! (`src/amneziawg/connector.rs`), far from any handle to the service task
//! whose end the host observes. When its receive path is unrecoverable,
//! the engine must stop rather than report healthy over a tunnel that
//! cannot hear its peer -- and the only route from there to
//! `control::run_prepared` is a process-global, the same pattern as the
//! endpoint registry and the traffic counters, resting on the documented
//! one-service-per-process invariant (`src/control/mod.rs`).
//!
//! In the standalone server binary nothing subscribes, so `report` is a
//! logged no-op there: a proxy server with many outbounds must not die
//! because one of them lost a socket.

use std::sync::LazyLock;

use log::{error, info};
use tokio::sync::watch;

static FATAL: LazyLock<watch::Sender<Option<String>>> =
    LazyLock::new(|| watch::channel(None).0);

/// Report a condition the engine cannot survive. The first report of a
/// session wins; later ones are logged and dropped, because the host
/// should hear the original cause, not the loudest consequence.
pub fn report(reason: String) {
    let stored = FATAL.send_if_modified(|slot| {
        if slot.is_none() {
            *slot = Some(reason.clone());
            true
        } else {
            false
        }
    });
    if stored {
        error!("fatal: {reason}");
    } else {
        info!("fatal (already reported, dropped): {reason}");
    }
}

/// Watch for a fatal report. The value is `None` until one arrives.
pub fn subscribe() -> watch::Receiver<Option<String>> {
    FATAL.subscribe()
}

/// Clear the slot. Called at the start of each service session, so a
/// reason from a previous session cannot stop the next one.
pub fn reset() {
    FATAL.send_replace(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The channel is process-global; tests that touch it must not
    /// interleave, the same rule as `outbound_stats::REGISTRY_TEST_LOCK`.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn the_first_reason_wins_and_reset_clears_it() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();

        let rx = subscribe();
        assert_eq!(*rx.borrow(), None);

        report("first".to_string());
        report("second".to_string());
        assert_eq!(rx.borrow().as_deref(), Some("first"));

        reset();
        assert_eq!(*rx.borrow(), None);
    }

    #[tokio::test]
    async fn a_subscriber_is_woken_by_a_report() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();

        let mut rx = subscribe();
        report("boom".to_string());
        let value = rx.wait_for(|slot| slot.is_some()).await.unwrap();
        assert_eq!(value.as_deref(), Some("boom"));

        reset();
    }
}
```

Note: `TEST_LOCK.lock().unwrap()` will poison on a failed assertion in another test; if that ever bites, switch to `unwrap_or_else(|e| e.into_inner())` like `ENDPOINTS` in `endpoint.rs:48`.

- [ ] **Step 2: Declare the module in both crate roots**

In `src/lib.rs`, directly below `mod amneziawg;` (line 59), add:

```rust
mod fatal;
```

(The crate-level `#![allow(dead_code)]` at the top of `lib.rs` covers any per-build unused halves.)

In `src/main.rs`, directly below `mod dns;` (line 13), add:

```rust
// The tunnel reports into this module in both builds, but only the
// library's control layer subscribes -- the standalone server must not
// die because one outbound lost a socket. So the subscribing half has no
// caller in this binary, which is a property of the build.
#[allow(dead_code)]
mod fatal;
```

- [ ] **Step 3: Run the new tests**

Run: `cargo test fatal::`
Expected: 2 passed.

- [ ] **Step 4: Confirm both crates still build**

Run: `cargo build && cargo test --lib fatal:: 2>&1 | tail -3`
Expected: clean build, tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/fatal.rs src/lib.rs src/main.rs
git commit -m "fatal: a process-global signal for deaths the service task cannot see"
```

---

### Task 2: `control` — a fatal report ends the service with its reason

**Files:**
- Modify: `src/control/mod.rs` (imports at line 13, `run_prepared` at lines 540-579, tests module)

- [ ] **Step 1: Write the failing tests for the watcher seam**

In the `tests` module of `src/control/mod.rs` (it already has `use super::*;` and uses `#[tokio::test]` elsewhere in the file), add:

```rust
    /// The watcher takes its receivers as parameters precisely so these
    /// tests can build their own channels and never touch the global.
    #[tokio::test]
    async fn a_fatal_report_forwards_shutdown_and_carries_its_reason() {
        let (fatal_tx, fatal_rx) = tokio::sync::watch::channel(None);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (forward_tx, forward_rx) = oneshot::channel::<()>();
        let watcher = tokio::spawn(shutdown_or_fatal(shutdown_rx, fatal_rx, forward_tx));

        fatal_tx.send_replace(Some("receive path died".to_string()));

        forward_rx.await.expect("the merged shutdown must fire");
        assert_eq!(
            watcher.await.unwrap().as_deref(),
            Some("receive path died")
        );
        drop(shutdown_tx);
    }

    #[tokio::test]
    async fn a_host_stop_forwards_shutdown_without_a_reason() {
        let (_fatal_tx, fatal_rx) = tokio::sync::watch::channel(None::<String>);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (forward_tx, forward_rx) = oneshot::channel::<()>();
        let watcher = tokio::spawn(shutdown_or_fatal(shutdown_rx, fatal_rx, forward_tx));

        shutdown_tx.send(()).unwrap();

        forward_rx.await.expect("the merged shutdown must fire");
        assert_eq!(watcher.await.unwrap(), None);
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test control::tests::a_fatal_report -- --nocapture 2>&1 | tail -5`
Expected: compile error — `shutdown_or_fatal` not found.

- [ ] **Step 3: Implement `shutdown_or_fatal`**

In `src/control/mod.rs`, change the import at line 13 from `use tokio::sync::oneshot;` to:

```rust
use tokio::sync::{oneshot, watch};
```

Add above `run_prepared`:

```rust
/// Merge the two ways a service can be told to stop into the one oneshot
/// the TUN honours: the host's shutdown signal, or a fatal report from a
/// component with no handle to the service task (see `crate::fatal`).
///
/// Returns the fatal reason when that is what fired, `None` for a host
/// stop. Takes its receivers as parameters so tests can supply their own
/// channels instead of the process-global.
async fn shutdown_or_fatal(
    shutdown_rx: oneshot::Receiver<()>,
    mut fatal_rx: watch::Receiver<Option<String>>,
    forward_tx: oneshot::Sender<()>,
) -> Option<String> {
    let reason = tokio::select! {
        _ = shutdown_rx => None,
        reason = async {
            match fatal_rx.wait_for(|slot| slot.is_some()).await {
                Ok(slot) => slot.clone(),
                // The production sender is a static and cannot drop; a
                // closed channel means no fatal is ever coming.
                Err(_) => std::future::pending().await,
            }
        } => reason,
    };
    let _ = forward_tx.send(());
    reason
}
```

- [ ] **Step 4: Run the seam tests**

Run: `cargo test control::tests::a_fatal_report control::tests::a_host_stop 2>&1 | tail -3`
Expected: 2 passed.

- [ ] **Step 5: Wire it into `run_prepared`**

Replace the body of `run_prepared` (lines 540-579) with:

```rust
pub async fn run_prepared(
    prepared: PreparedService,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let PreparedService {
        tun_config,
        server_configs,
        mut dns_registry,
        policy,
    } = prepared;

    // A fatal from a previous session must not stop this one.
    crate::fatal::reset();

    // Start TCP servers (like mixed)
    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles.extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // The TUN honours one oneshot. Merge the host's shutdown and the
    // process-wide fatal signal into it, rather than selecting over the
    // TUN future itself -- dropping that future mid-poll would skip the
    // graceful teardown that releases the descriptor.
    let (tun_shutdown_tx, tun_shutdown_rx) = oneshot::channel();
    let stop_watcher = tokio::spawn(shutdown_or_fatal(
        shutdown_rx,
        crate::fatal::subscribe(),
        tun_shutdown_tx,
    ));

    // Runs until shutdown. Who closes the descriptor follows from the policy:
    // whoever created the device closes it, and nobody else.
    #[cfg(any(unix, windows))]
    let result = run_tun_from_config(tun_config, tun_shutdown_rx, policy.close_fd_on_drop()).await;
    #[cfg(not(any(unix, windows)))]
    let result = {
        // Consumed only by the TUN branch, which this platform does not have.
        let _ = policy;
        let _ = tun_shutdown_rx;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is not supported on this platform",
        ))
    };

    // Cleanup any servers when TUN stops
    for handle in join_handles {
        handle.abort();
    }

    // The watcher either fired (and is finished -- a finished task
    // survives the abort and still yields its value) or the TUN ended on
    // its own (and the watcher is moot). A fatal reason overrides the
    // Ok(()) the TUN returns for what it saw as a requested shutdown; the
    // ExitGuard then reports it through on_exit like any other failure.
    stop_watcher.abort();
    match stop_watcher.await {
        Ok(Some(reason)) => Err(std::io::Error::other(reason)),
        _ => result,
    }
}
```

- [ ] **Step 6: Run the whole control test module**

Run: `cargo test control:: 2>&1 | tail -5`
Expected: all pass (the existing exit-contract tests exercise `start_with`, which bypasses `run_prepared`, so they must be untouched by this change).

- [ ] **Step 7: Commit**

```bash
git add src/control/mod.rs
git commit -m "control: a fatal report stops the service and carries its reason"
```

---

### Task 3: recv error classification in `tunnel.rs`

**Files:**
- Modify: `src/amneziawg/tunnel.rs` (new items near the constants at the top; tests in the existing `tests` module)

- [ ] **Step 1: Write the failing tests**

In the `tests` module of `src/amneziawg/tunnel.rs`, add:

```rust
    /// EMSGSIZE on a connected UDP socket is a deferred send-path error --
    /// an ICMP Fragmentation Needed for a datagram *we* sent, latched on
    /// the socket and delivered by the next syscall (udp(7)). One of these
    /// killed inbound for an entire session (KVN, 2026-08-29); it must be
    /// survivable, and it must shrink the trailer window whose growth
    /// produces the oversized sends.
    #[test]
    fn emsgsize_is_survivable_and_resets_the_trailer_window() {
        let e = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert_eq!(
            classify_recv_error(&e),
            RecvErrorAction::ResetTrailerWindow
        );
    }

    #[test]
    fn icmp_echoes_are_ignored() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::NetworkDown,
            ErrorKind::Interrupted,
        ] {
            assert_eq!(
                classify_recv_error(&std::io::Error::from(kind)),
                RecvErrorAction::Ignore,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_unrecognised_error_is_suspect_but_not_fatal_on_its_own() {
        let e = std::io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(classify_recv_error(&e), RecvErrorAction::Suspect);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test amneziawg::tunnel::tests::emsgsize 2>&1 | tail -5`
Expected: compile error — `classify_recv_error` not found.

- [ ] **Step 3: Implement the classification**

In `src/amneziawg/tunnel.rs`, below the `TRAILER_PROBE_INTERVAL` constant, add:

```rust
/// What a recv error on the connected endpoint socket means.
///
/// On a connected UDP socket nearly every recv error is an asynchronous
/// echo of the past -- an ICMP reply to something sent earlier, latched
/// on the socket and delivered by the next syscall (udp(7)). None of them
/// say the socket itself is broken, so none of them justify killing
/// inbound for the rest of the session: the cost of wrongly continuing is
/// a log line, the cost of wrongly stopping is a tunnel that is deaf
/// until the user reconnects.
#[derive(Debug, PartialEq, Eq)]
enum RecvErrorAction {
    /// Routine. Log at debug and keep receiving.
    Ignore,
    /// EMSGSIZE: a datagram *we* sent exceeded the path MTU. With
    /// AmneziaWG 3.1 random trailers that means the trailer window has
    /// outgrown the path -- it is sized from a high-water mark of
    /// datagrams seen, which a higher-MTU peer pushes past what this
    /// path carries. Warn, shrink the window, keep receiving.
    ResetTrailerWindow,
    /// Unrecognised. Warn and keep receiving -- but a socket producing
    /// nothing but errors is dead, which is RecvErrorStreak's call.
    Suspect,
}

fn classify_recv_error(e: &std::io::Error) -> RecvErrorAction {
    use std::io::ErrorKind;
    // No stable ErrorKind exists for EMSGSIZE; endpoint.rs matches raw
    // errno the same way for EINVAL.
    if e.raw_os_error() == Some(libc::EMSGSIZE) {
        return RecvErrorAction::ResetTrailerWindow;
    }
    match e.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown
        | ErrorKind::Interrupted => RecvErrorAction::Ignore,
        _ => RecvErrorAction::Suspect,
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test amneziawg::tunnel::tests:: 2>&1 | tail -3`
Expected: all pass, including the three new ones.

- [ ] **Step 5: Commit**

```bash
git add src/amneziawg/tunnel.rs
git commit -m "awg: classify recv errors instead of dying on the first strange one"
```

---

### Task 4: the consecutive-error streak

**Files:**
- Modify: `src/amneziawg/tunnel.rs` (below `classify_recv_error`; tests in the existing `tests` module)

- [ ] **Step 1: Write the failing tests**

In the `tests` module, add:

```rust
    #[test]
    fn back_to_back_errors_back_off_and_eventually_give_up() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        let mut gave_up_at = None;
        for i in 1..=RECV_ERROR_FATAL_STREAK {
            // 10ms apart: well inside the streak window.
            let now = t0 + std::time::Duration::from_millis(10 * u64::from(i));
            match streak.on_error(now) {
                StreakVerdict::KeepGoing => {
                    assert!(i <= RECV_ERROR_BACKOFF_AFTER, "no backoff at error {i}")
                }
                StreakVerdict::Backoff => {
                    assert!(i > RECV_ERROR_BACKOFF_AFTER, "backoff too early at {i}")
                }
                StreakVerdict::GiveUp => {
                    gave_up_at = Some(i);
                    break;
                }
            }
        }
        assert_eq!(gave_up_at, Some(RECV_ERROR_FATAL_STREAK));
    }

    /// A peer that is merely down produces one latched ICMP echo per
    /// handshake retry, seconds apart -- that must never accumulate into
    /// a death, no matter how long the outage lasts.
    #[test]
    fn spaced_errors_never_accumulate() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        for i in 0..500u64 {
            let now = t0 + std::time::Duration::from_secs(5 * i);
            assert!(matches!(streak.on_error(now), StreakVerdict::KeepGoing));
        }
    }

    #[test]
    fn a_successful_recv_resets_the_streak() {
        let t0 = std::time::Instant::now();
        let mut streak = RecvErrorStreak::new();
        for i in 1..=20u64 {
            streak.on_error(t0 + std::time::Duration::from_millis(10 * i));
        }
        streak.on_success();
        assert!(matches!(
            streak.on_error(t0 + std::time::Duration::from_millis(500)),
            StreakVerdict::KeepGoing
        ));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test amneziawg::tunnel::tests::back_to_back 2>&1 | tail -5`
Expected: compile error — `RecvErrorStreak` not found.

- [ ] **Step 3: Implement the streak**

Below `classify_recv_error`, add:

```rust
/// An error within this much of the previous one continues the streak;
/// a longer gap starts a new streak of one. A blocked recv produces
/// neither success nor error, so only a socket returning errors
/// continuously can accumulate.
const RECV_ERROR_STREAK_WINDOW: Duration = Duration::from_secs(1);

/// Streak length past which the loop sleeps before the next recv, so a
/// socket stuck returning errors does not spin hot.
const RECV_ERROR_BACKOFF_AFTER: u32 = 4;

/// How long that sleep is.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Streak length at which the receive path is declared dead: with the
/// backoff, roughly five seconds of a socket producing nothing but
/// errors. Reaching this is the only way out of the decapsulate loop.
const RECV_ERROR_FATAL_STREAK: u32 = 100;

/// Consecutive-error accounting for the receive loop. Time is a
/// parameter rather than read here, so tests inject it.
struct RecvErrorStreak {
    count: u32,
    last: Option<std::time::Instant>,
}

#[derive(Debug)]
enum StreakVerdict {
    KeepGoing,
    Backoff,
    GiveUp,
}

impl RecvErrorStreak {
    fn new() -> Self {
        Self {
            count: 0,
            last: None,
        }
    }

    fn on_success(&mut self) {
        self.count = 0;
        self.last = None;
    }

    fn on_error(&mut self, now: std::time::Instant) -> StreakVerdict {
        self.count = match self.last {
            Some(prev) if now.duration_since(prev) <= RECV_ERROR_STREAK_WINDOW => self.count + 1,
            _ => 1,
        };
        self.last = Some(now);
        if self.count >= RECV_ERROR_FATAL_STREAK {
            StreakVerdict::GiveUp
        } else if self.count > RECV_ERROR_BACKOFF_AFTER {
            StreakVerdict::Backoff
        } else {
            StreakVerdict::KeepGoing
        }
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test amneziawg::tunnel::tests:: 2>&1 | tail -3`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/amneziawg/tunnel.rs
git commit -m "awg: a time-windowed error streak tells a sick socket from a down peer"
```

---

### Task 5: the receive loop survives, and its death is loud

**Files:**
- Modify: `src/amneziawg/tunnel.rs` (`TunnelRuntime` struct at lines 32-48, `start` at lines 93-133 and 173-178, `decapsulate_loop` at lines 181-240)

- [ ] **Step 1: Write the failing test**

In the `tests` module, add (reuses the existing `real_world_params`, `keypair` helpers and `convert_amnezia_config` import):

```rust
    /// The dead flag is what the connector polls to rebuild a tunnel in
    /// the standalone binary; a fresh runtime must start alive.
    #[tokio::test]
    async fn a_fresh_tunnel_runtime_is_not_dead() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (secret, _) = keypair(1);
        let (_, server_public) = keypair(2);
        let runtime = TunnelRuntime::start(
            secret,
            server_public,
            Some([0x33u8; 32]),
            Some(25),
            config,
            addr,
        )
        .await
        .unwrap();
        assert!(!runtime.is_dead());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test amneziawg::tunnel::tests::a_fresh_tunnel_runtime 2>&1 | tail -5`
Expected: compile error — no method `is_dead`.

- [ ] **Step 3: Rework the runtime and the loop**

In `src/amneziawg/tunnel.rs`:

3a. Extend the imports at line 8 to include `AtomicBool`:

```rust
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
```

3b. Add two fields to `TunnelRuntime` (after `ip_from_tunnel_rx`):

```rust
    /// Outer datagrams successfully received, ever. The trailer probe
    /// reads this to tell "the peer answers but nothing parses" from
    /// "nothing arrives at all" -- see probe_message.
    datagrams_received: Arc<AtomicUsize>,
    /// Set when the receive loop has terminated. The engine hears about
    /// that through crate::fatal; the standalone binary has no engine, so
    /// the connector polls this instead and rebuilds the tunnel.
    dead: Arc<AtomicBool>,
```

3c. In `start`, after the `packets_offered` line (line 93), add:

```rust
        let datagrams_received = Arc::new(AtomicUsize::new(0));
        let dead = Arc::new(AtomicBool::new(false));
```

3d. Replace the `recv_task` block (lines 107-114) with:

```rust
        // Task 1: Read UDP datagrams from server, decapsulate, send IP packets to stack
        let recv_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            let tx = ip_from_tunnel_tx;
            let received = datagrams_received.clone();
            let dead = dead.clone();
            tokio::spawn(async move {
                let reason = decapsulate_loop(tunn, udp, tx, received).await;
                // The loop only returns when the receive path is
                // unrecoverable. Say so loudly: an engine that keeps
                // reporting healthy over a tunnel that cannot hear its
                // peer is worse than a stopped one, because the host can
                // react to a stop and cannot detect deafness.
                dead.store(true, Ordering::SeqCst);
                error!("AmneziaWG receive path failed: {reason}");
                crate::fatal::report(format!("AmneziaWG receive path failed: {reason}"));
            })
        };
```

3e. In the `Ok(Arc::new(Self { ... }))` at lines 173-177, add the new fields:

```rust
        Ok(Arc::new(Self {
            ip_to_tunnel_tx,
            ip_from_tunnel_rx: ParkingMutex::new(Some(ip_from_tunnel_rx)),
            datagrams_received,
            dead,
            abort_handles,
        }))
```

3f. Add the accessor to `impl TunnelRuntime` (after `start`):

```rust
    /// Whether the receive loop has terminated. A dead runtime never
    /// recovers; the caller's move is to drop it and build a new one.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
```

3g. Replace `decapsulate_loop` (lines 181-240) with:

```rust
async fn decapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    tx: mpsc::Sender<Vec<u8>>,
    datagrams_received: Arc<AtomicUsize>,
) -> String {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut out = vec![0u8; MAX_UDP_SIZE];
    // Reused for every packet this loop sends. See the comment in
    // drain_queued_packets for why the copy is needed at all.
    let mut packet = Vec::new();
    let mut streak = RecvErrorStreak::new();

    loop {
        let n = match udp.recv(&mut buf).await {
            Ok(n) => {
                streak.on_success();
                // Counted before decapsulation: arrival is the fact the
                // trailer probe needs, parseability is a separate one.
                datagrams_received.fetch_add(1, Ordering::Relaxed);
                n
            }
            Err(e) => {
                match classify_recv_error(&e) {
                    RecvErrorAction::Ignore => {
                        debug!("AmneziaWG UDP recv transient error, continuing: {}", e);
                    }
                    RecvErrorAction::ResetTrailerWindow => {
                        warn!(
                            "AmneziaWG: a sent datagram exceeded the path MTU \
                             (EMSGSIZE on the socket); resetting the trailer window \
                             and continuing"
                        );
                        tunn.lock().reset_udp_window();
                    }
                    RecvErrorAction::Suspect => {
                        warn!("AmneziaWG UDP recv error, continuing: {}", e);
                    }
                }
                match streak.on_error(std::time::Instant::now()) {
                    StreakVerdict::KeepGoing => {}
                    StreakVerdict::Backoff => tokio::time::sleep(RECV_ERROR_BACKOFF).await,
                    StreakVerdict::GiveUp => {
                        return format!(
                            "{RECV_ERROR_FATAL_STREAK} consecutive recv errors, last: {e}"
                        );
                    }
                }
                continue;
            }
        };

        // Decapsulate with lock held briefly
        let result = {
            let mut tunn = tunn.lock();
            tunn.decapsulate(None, &buf[..n], &mut out)
        };

        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!("AmneziaWG decapsulate error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                packet.clear();
                packet.extend_from_slice(data);
                send_to_network(&tunn, &udp, &packet, "handshake").await;
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet).await;
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                if tx.try_send(data.to_vec()).is_err() {
                    // The virtual stack is not keeping up. Dropping is correct
                    // for a tunnel -- the inner protocol will retransmit -- but
                    // it is worth seeing when throughput is being lost.
                    debug!("AmneziaWG: virtual stack queue full, dropping inbound packet");
                }
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet).await;
            }
        }
    }
}
```

- [ ] **Step 4: Run the whole tunnel test module**

Run: `cargo test amneziawg:: 2>&1 | tail -5`
Expected: all pass, including `a_fresh_tunnel_runtime_is_not_dead`.

- [ ] **Step 5: Commit**

```bash
git add src/amneziawg/tunnel.rs
git commit -m "awg: recv errors are weather; a truly dead receive path stops the engine"
```

---

### Task 6: the probe says what it actually knows

**Files:**
- Modify: `src/amneziawg/tunnel.rs` (`start` probe block at lines 156-171, `trailer_probe_loop` at lines 394-445, tests)

- [ ] **Step 1: Write the failing test**

In the `tests` module, add:

```rust
    /// When nothing has arrived at all, the trailer setting is
    /// unfalsifiable -- the message must not point at it. That hint sent
    /// a real debugging session down a false path (KVN, 2026-08-29) while
    /// the actual fault was a dead receive loop.
    #[test]
    fn the_probe_does_not_blame_trailers_when_nothing_arrived() {
        let silent = probe_message(221, "off", 0);
        assert!(silent.contains("nothing received"), "got: {silent}");
        assert!(
            !silent.contains("set random_trailers to match the peer"),
            "got: {silent}"
        );

        let chatty = probe_message(221, "off", 7);
        assert!(
            chatty.contains("set random_trailers to match the peer"),
            "got: {chatty}"
        );
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test amneziawg::tunnel::tests::the_probe_does_not_blame 2>&1 | tail -5`
Expected: compile error — `probe_message` not found.

- [ ] **Step 3: Implement the message split and thread the counter through**

3a. Below `trailers_look_wrong`, add:

```rust
/// The flip announcement, worded by what actually arrived.
///
/// Datagrams arrived but no handshake completed: the peer answers and
/// nothing parses, which genuinely smells like a framing mismatch.
/// Nothing arrived in the whole probe interval: the trailer setting is
/// unfalsifiable, so the message must not single it out.
fn probe_message(offered: usize, new_state: &str, arrived_since_last_probe: usize) -> String {
    if arrived_since_last_probe == 0 {
        format!(
            "AmneziaWG: no handshake after {offered} packets and nothing received from \
             the peer; the endpoint may be unreachable or blocked, or the obfuscation \
             parameters may not match -- retrying with random trailers {new_state} anyway."
        )
    } else {
        format!(
            "AmneziaWG: no handshake after {offered} packets; retrying with random \
             trailers {new_state}. If this is what fixes the tunnel, set random_trailers \
             to match the peer."
        )
    }
}
```

3b. Change `trailer_probe_loop`'s signature and its announcement. The signature gains the counter:

```rust
async fn trailer_probe_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    keys: TunnelKeys,
    packets_offered: Arc<AtomicUsize>,
    datagrams_received: Arc<AtomicUsize>,
    interval: Duration,
) {
    let mut random_trailers = keys.amnezia.random_trailers;
    let mut received_at_last_probe = datagrams_received.load(Ordering::Relaxed);

    loop {
        tokio::time::sleep(interval).await;

        let received_now = datagrams_received.load(Ordering::Relaxed);
        let arrived = received_now - received_at_last_probe;
        received_at_last_probe = received_now;

        let offered = packets_offered.load(Ordering::Relaxed);
        {
            let tunn = tunn.lock();
            if !trailers_look_wrong(tunn.stats().0, offered) {
                continue;
            }
        }

        random_trailers = !random_trailers;
        let mut amnezia = keys.amnezia.clone();
        amnezia.random_trailers = random_trailers;
```

and in the `Ok(replacement)` arm, replace the `warn!` with:

```rust
            Ok(replacement) => {
                *tunn.lock() = replacement;
                let state = if random_trailers { "on" } else { "off" };
                warn!("{}", probe_message(offered, state, arrived));
            }
```

(the rest of the function is unchanged).

3c. In `start`, pass the counter at the probe spawn (lines 164-169):

```rust
            let probe_task = tokio::spawn(trailer_probe_loop(
                tunn.clone(),
                rebuild,
                packets_offered.clone(),
                datagrams_received.clone(),
                TRAILER_PROBE_INTERVAL,
            ));
```

3d. Fix the existing async probe test `a_stalled_31_tunnel_probes_its_way_back_to_30_framing` — its spawn gains the argument:

```rust
        tokio::spawn(trailer_probe_loop(
            tunn.clone(),
            keys,
            offered,
            Arc::new(AtomicUsize::new(0)),
            interval,
        ));
```

- [ ] **Step 4: Run the tunnel tests**

Run: `cargo test amneziawg:: 2>&1 | tail -5`
Expected: all pass, including the reworded-probe test and the pre-existing probe test.

- [ ] **Step 5: Commit**

```bash
git add src/amneziawg/tunnel.rs
git commit -m "awg: the trailer hint no longer blames a setting silence cannot falsify"
```

---

### Task 7: the connector rebuilds a dead tunnel

**Files:**
- Modify: `src/amneziawg/connector.rs` (`TunnelState` at lines 21-24, `ensure_initialized` at lines 124-179)

- [ ] **Step 1: Rename the field and add the dead check**

In `src/amneziawg/connector.rs`, change `TunnelState` (lines 21-24) to:

```rust
struct TunnelState {
    runtime: Arc<TunnelRuntime>,
    request_tx: mpsc::Sender<NetStackRequest>,
}
```

Replace the head of `ensure_initialized` (lines 128-131) with:

```rust
        let mut state = self.state.lock().await;
        if let Some(ref s) = *state {
            if s.runtime.is_dead() {
                // The receive path died and reported fatal. Under the
                // mobile engine that has already stopped the service; in
                // the standalone binary nobody listens, so recovery is
                // here -- drop the dead runtime and rebuild on this
                // connection. Streams on the old netstack are lost, which
                // they already were.
                info!("AmneziaWG: tunnel receive path died; rebuilding the tunnel");
                *state = None;
            } else {
                return Ok(s.request_tx.clone());
            }
        }
```

and the state installation (lines 173-176) to match the renamed field:

```rust
        *state = Some(TunnelState {
            runtime: tunnel_runtime,
            request_tx: request_tx.clone(),
        });
```

- [ ] **Step 2: Build and run the module tests**

Run: `cargo build && cargo test amneziawg:: 2>&1 | tail -3`
Expected: clean build, all pass. (The rebuild path itself needs a resolver and a live socket to exercise; it is covered by the `is_dead` unit test from Task 5 plus manual verification in Task 8.)

- [ ] **Step 3: Commit**

```bash
git add src/amneziawg/connector.rs
git commit -m "awg: the connector rebuilds a tunnel whose receive path died"
```

---

### Task 8: changelog, lint, full suite

**Files:**
- Modify: `CHANGELOG.md` (new `Unreleased` section above `## v0.2.16`)

- [ ] **Step 1: Write the changelog entry**

At the top of `CHANGELOG.md`, between `# Changelog` and `## v0.2.16`, insert:

```markdown
## Unreleased

### The AmneziaWG receive path survives errors, and its death stops the engine

One `EMSGSIZE` on the tunnel's UDP socket used to kill inbound for the
rest of the session while the engine kept reporting healthy. On a
connected UDP socket that error is a deferred echo of our own send
exceeding the path MTU -- with 3.1 random trailers, the trailer window
grows past what the path carries when the peer runs a higher MTU -- and
the socket is fine afterwards. The receive loop now classifies recv
errors and continues: routine ICMP echoes are logged and dropped,
`EMSGSIZE` additionally shrinks the trailer window, and unknown errors
are tolerated too. Only a socket producing nothing but errors for ~5
seconds straight ends the loop -- and that now stops the engine with the
reason (the stopped callback on iOS/macOS, `shoes_get_last_error` on
Android) instead of leaving `shoes_is_running()` true over a deaf tunnel.
The standalone binary instead rebuilds the tunnel on the next connection.

The trailer-probe hint no longer says "set random_trailers to match the
peer" when nothing was received from the peer at all -- silence cannot
falsify the trailer setting, and the old wording sent a real debugging
session down a false path.
```

- [ ] **Step 2: Full verification**

Run: `cargo fmt --check && cargo clippy --all-targets 2>&1 | tail -5 && cargo test 2>&1 | tail -5`
Expected: no formatting diffs, no new clippy warnings, full suite green. Fix anything that appears before committing.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog for the AmneziaWG receive-path fixes"
```

- [ ] **Step 4: Manual verification note**

The full chain (real recv error → fatal → `on_exit` → host callback)
crosses a real TUN device and a kernel-latched socket error, so it is
verified against the KVN reproduction rather than in CI: peer
`docker-amneziawg` at default 1420 MTU, client config `mtu: 1280`,
`random_trailers: on`, sustained traffic. Expected: on an `EMSGSIZE` the
log shows the trailer-window reset and the tunnel keeps carrying traffic;
no nine-minute deaf-but-"Connected" state is reachable.
