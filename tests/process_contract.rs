//! The process contract an operator such as awg-manager holds an engine to:
//! `check <config>`, `version`, and `SIGHUP` as an immediate reload. These
//! drive the real binary, because every claim is about `main.rs`.
//!
//! See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 1".
//!
//! The signal tests are Unix-only, and so are the helpers only they use:
//! the test matrix includes Windows, where an unused helper is a warning.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::process::Stdio;

/// A child that dies with the test, whichever way the test ends.
#[cfg(unix)]
struct Child(std::process::Child);

#[cfg(unix)]
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn shoes_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_shoes"))
}

/// `N` free ports, none of them ever handed out before in this process.
///
/// A port is free only while it is being allocated, and the kernel hands a
/// released one back readily. Every test here is a thread of one process
/// that gives its ports to a shoes it spawns, so a port given to two tests
/// has two children racing to bind it: the loser never starts, and a probe
/// of the port is answered by the winner. That was the one Linux failure of
/// `sighup_reloads_immediately_even_with_no_reload`. Remembering every port
/// handed out rules it out within the binary; the listeners stay bound
/// until all `N` are picked, so one call cannot repeat itself either.
#[cfg(unix)]
fn free_ports<const N: usize>() -> [u16; N] {
    static HANDED_OUT: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut handed_out = HANDED_OUT.lock().unwrap();
    let mut held = Vec::new();
    let mut ports = Vec::with_capacity(N);
    while ports.len() < N {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if !handed_out.contains(&port) {
            handed_out.push(port);
            ports.push(port);
        }
        held.push(listener);
    }
    ports.try_into().unwrap()
}

/// The tests in this file run as threads of one process, each spawning a
/// shoes that binds the ports it was given. A port handed to two of them
/// makes the second shoes fail to bind while the first answers for it.
#[cfg(unix)]
#[test]
fn free_ports_never_hands_out_a_port_twice() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2000 {
        let [port] = free_ports::<1>();
        assert!(seen.insert(port), "port {port} handed out twice");
    }
}

fn socks_config(port: u16) -> String {
    format!("- address: 127.0.0.1:{port}\n  protocol:\n    type: socks\n")
}

#[cfg(unix)]
async fn listening(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

#[cfg(unix)]
async fn wait_until(addr: SocketAddr, up: bool) {
    // Fifteen seconds: the first execution of a freshly linked binary can
    // take over a second on macOS before `main` runs, and the tests in
    // this file all pay it at once.
    for _ in 0..300 {
        if listening(addr).await == up {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{addr} never became up={up}");
}

/// Wait until the child has a listener accepting on `addr`. Its own line
/// first, so the listener is known to be this child's attempt; then a
/// connect, because the line is printed before the bind and a bind that
/// fails prints it too. The connect cannot be answered by another test's
/// child: `free_ports` gives each port to one test.
#[cfg(unix)]
async fn wait_for_listener(stdout: &mut Stdout, addr: SocketAddr) {
    stdout.wait_for(&format!("server at {addr}"));
    wait_until(addr, true).await;
}

#[cfg(unix)]
fn sighup(child: &Child) {
    // SAFETY: a plain signal to a child this test owns.
    unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) };
}

/// The child's stdout, line by line, read on its own thread so the pipe
/// never fills and the test can wait for the process to announce a state
/// instead of guessing how long it takes to reach it.
#[cfg(unix)]
struct Stdout {
    rx: std::sync::mpsc::Receiver<String>,
    seen: Vec<String>,
}

#[cfg(unix)]
impl Stdout {
    fn tap(child: &mut Child) -> Self {
        use std::io::BufRead;
        let stdout = child.0.stdout.take().expect("spawned with a piped stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            rx,
            seen: Vec::new(),
        }
    }

    /// Block until a line containing `needle` is printed; fail if none is.
    fn wait_for(&mut self, needle: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(line) => {
                    let hit = line.contains(needle);
                    self.seen.push(line);
                    if hit {
                        return;
                    }
                }
                Err(_) => panic!(
                    "the process never printed {needle:?}; stdout so far:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Every line printed so far, plus whatever arrives until the pipe
    /// closes (the child is dead) or a few seconds pass.
    fn rest(mut self) -> Vec<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(_) => break self.seen,
            }
        }
    }
}

#[test]
fn check_exits_zero_on_a_valid_config_and_one_with_the_error_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.yaml");
    std::fs::write(&good, socks_config(1080)).unwrap();
    let ok = std::process::Command::new(shoes_bin())
        .arg("check")
        .arg(&good)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "- address: 127.0.0.1:1080\n  protocol:\n    type: nonsense\n",
    )
    .unwrap();
    let err = std::process::Command::new(shoes_bin())
        .arg("check")
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(err.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&err.stderr).contains("nonsense"),
        "stderr should name the bad value: {}",
        String::from_utf8_lossy(&err.stderr)
    );
}

/// A path that does not exist is the first thing an operator's tooling gets
/// wrong, and it must be an exit code, not a panic: the file watcher used
/// to be set up before validation and unwrapped the missing path, which
/// exited 101 where 1 was promised.
#[test]
fn check_on_a_missing_file_is_an_exit_code_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.yaml");
    let out = std::process::Command::new(shoes_bin())
        .arg("check")
        .arg(&missing)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        !stderr.contains("panic"),
        "a missing file must not panic: {stderr}"
    );
    assert!(
        stderr.contains("missing.yaml"),
        "the message should name the file: {stderr}"
    );
}

#[test]
fn version_prints_the_crate_version() {
    let out = std::process::Command::new(shoes_bin())
        .arg("version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("shoes {}", env!("CARGO_PKG_VERSION"))
    );
}

/// The operator has finished writing the file when it signals, so there is
/// no debounce; and `--no-reload` disables the file watcher, not the
/// operator.
#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_immediately_even_with_no_reload() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let [first, second] = free_ports::<2>();
    assert_ne!(first, second);
    std::fs::write(&config, socks_config(first)).unwrap();
    let mut child = Child(
        std::process::Command::new(shoes_bin())
            .arg("--no-reload")
            .arg(&config)
            .stdout(Stdio::piped())
            // Inherited, so a failed bind is in the test's output.
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdout = Stdout::tap(&mut child);
    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], first))).await;

    std::fs::write(&config, socks_config(second)).unwrap();
    let started = std::time::Instant::now();
    sighup(&child);
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], second))).await;
    wait_until(first_addr, false).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a SIGHUP reload must not wait for the 3 s file-watcher debounce"
    );
    drop(child);
}

/// A `SIGHUP` that lands while the process is still starting -- config
/// read, handler installed, listeners not yet bound -- is held until the
/// serve loop can act on it, and then honoured. The config is rewritten
/// before the burst, so a signal that was merely swallowed (the "ignore"
/// disposition `main` starts with) would leave the first listener up and
/// this test waiting for the second one.
///
/// The burst starts on the first line the process prints, which comes after
/// the handler is installed and the first config is read, and before any
/// listener is bound. It cannot start earlier: a signal that arrives before
/// the loader has reached `main` kills any process, and nothing in `main.rs`
/// can close that window. From the first instruction of `main` the
/// disposition is "ignore" until the handler takes over, so the rest of
/// start-up is covered by this one synchronisation point rather than by a
/// guess at the timing.
#[cfg(unix)]
#[tokio::test]
async fn sighup_during_startup_is_buffered_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let [first, second] = free_ports::<2>();
    std::fs::write(&config, socks_config(first)).unwrap();
    let mut child = Child(
        std::process::Command::new(shoes_bin())
            .arg("--no-reload")
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdout = Stdout::tap(&mut child);
    stdout.wait_for("Starting");

    // The first config is already read; the reload the buffered signal
    // triggers must pick up this one.
    std::fs::write(&config, socks_config(second)).unwrap();

    // A burst rather than one signal, so that some land before the first
    // bind and some after it, whichever way the scheduler leans on this run.
    for _ in 0..20 {
        sighup(&child);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], second))).await;
    wait_until(first_addr, false).await;
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process must still be running after SIGHUPs through start-up"
    );
    drop(child);
}

/// The operator's usual sequence is "write the file, then signal", and with
/// the watcher on both announce the same edit. The watcher's event arrives
/// first, in milliseconds, and starts the three-second debounce; the signal
/// must cut that short rather than wait it out, and the pair must be one
/// reload, not an immediate one followed by a debounced one.
///
/// Synchronised on the process's own announcement of the debounce rather
/// than on a guessed sleep: that is the state the signal has to interrupt,
/// and it also proves the watcher's event was consumed before the signal
/// was sent, which is the case the coalescing is for.
#[cfg(unix)]
#[tokio::test]
async fn a_write_then_a_sighup_is_one_reload_not_two() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let [first, second] = free_ports::<2>();
    std::fs::write(&config, socks_config(first)).unwrap();
    let mut child = Child(
        std::process::Command::new(shoes_bin())
            // The watcher on: this is the case where two sources exist.
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdout = Stdout::tap(&mut child);
    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    // The child's line as well as a connect. A connect alone, answered by a
    // sibling test's process holding the same port, let the write below
    // land before this child read its config; it then started on the second
    // port and saw no change. That was this test's one Linux failure, a
    // child that started and never printed "Configs changed", and the shared
    // port behind it is what `free_ports` now rules out.
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], first))).await;

    std::fs::write(&config, socks_config(second)).unwrap();
    stdout.wait_for("Configs changed");
    let signalled = std::time::Instant::now();
    sighup(&child);
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], second))).await;
    wait_until(first_addr, false).await;
    assert!(
        signalled.elapsed() < std::time::Duration::from_secs(2),
        "a SIGHUP during the watcher's debounce must cut it short, not wait out the 3 s"
    );

    // Past the debounce: a stale event would have fired by now.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let _ = child.0.kill();
    let lines = stdout.rest();
    let restarts = lines
        .iter()
        .filter(|l| l.contains("Restarting servers.."))
        .count();
    assert_eq!(
        restarts,
        1,
        "one edit, one reload; stdout was:\n{}",
        lines.join("\n")
    );
    drop(child);
}

/// A watcher event for a file whose bytes did not change restarts nothing.
///
/// FSEvents on macOS can deliver a second event for one write after the
/// reload that write caused has drained the first, and a restart drops every
/// live connection. This test made that visible as two restarts for one
/// edit, intermittently, on macOS runners. Rewriting the same bytes produces
/// the same late event on demand on every platform.
#[cfg(unix)]
#[tokio::test]
async fn a_watcher_event_for_unchanged_bytes_restarts_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let [port] = free_ports::<1>();
    std::fs::write(&config, socks_config(port)).unwrap();
    let mut child = Child(
        std::process::Command::new(shoes_bin())
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdout = Stdout::tap(&mut child);
    wait_for_listener(&mut stdout, SocketAddr::from(([127, 0, 0, 1], port))).await;

    std::fs::write(&config, socks_config(port)).unwrap();
    stdout.wait_for("Configs changed");
    stdout.wait_for("Configs unchanged");

    let _ = child.0.kill();
    let lines = stdout.rest();
    assert!(
        !lines.iter().any(|l| l.contains("Restarting servers..")),
        "the same bytes are not an edit; stdout was:\n{}",
        lines.join("\n")
    );
    drop(child);
}
