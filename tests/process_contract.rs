//! The process contract an operator such as awg-manager holds an engine to:
//! `check <config>`, `version`, and `SIGHUP` as an immediate reload. These
//! drive the real binary, because every claim is about `main.rs`.
//!
//! See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 1".
//!
//! The signal tests are Unix-only, and so are the helpers only they use:
//! the test matrix includes Windows, where an unused helper is a warning.

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

/// `N` distinct free ports.
///
/// Every listener stays bound until all are allocated: binding and
/// releasing one at a time can hand the same port back twice, and a test
/// that reloads onto "a different port" then reloads onto the same one and
/// waits forever for the old listener to go away.
#[cfg(unix)]
fn free_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    ports.try_into().unwrap()
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

#[cfg(unix)]
fn sighup(child: &Child) {
    // SAFETY: a plain signal to a child this test owns.
    unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) };
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
    let child = Child(
        std::process::Command::new(shoes_bin())
            .arg("--no-reload")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    let second_addr: SocketAddr = format!("127.0.0.1:{second}").parse().unwrap();
    wait_until(first_addr, true).await;

    std::fs::write(&config, socks_config(second)).unwrap();
    let started = std::time::Instant::now();
    sighup(&child);
    wait_until(second_addr, true).await;
    wait_until(first_addr, false).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a SIGHUP reload must not wait for the 3 s file-watcher debounce"
    );
    drop(child);
}

/// A `SIGHUP` that lands while the process is still starting -- arguments
/// parsed, handler installed, listeners not yet bound -- is held until the
/// serve loop can act on it, not fatal.
///
/// The burst starts on the first line the process prints, which comes after
/// the handler is installed and before any listener is bound. It cannot
/// start earlier: a signal that arrives before the loader has reached
/// `main` kills any process, and nothing in `main.rs` can close that window.
/// From the first instruction of `main` the disposition is "ignore" until
/// the handler takes over, so the rest of start-up is covered by this one
/// synchronisation point rather than by a guess at the timing.
#[cfg(unix)]
#[tokio::test]
async fn sighup_during_startup_is_buffered_not_fatal() {
    use std::io::BufRead;

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let [port] = free_ports::<1>();
    std::fs::write(&config, socks_config(port)).unwrap();
    let mut child = Child(
        std::process::Command::new(shoes_bin())
            .arg("--no-reload")
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line.contains("Starting") {
                let _ = started_tx.send(());
            }
        }
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the process never announced start-up");

    // A burst rather than one signal, so that some land before the first
    // bind and some after it, whichever way the scheduler leans on this run.
    for _ in 0..20 {
        sighup(&child);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    wait_until(addr, true).await;
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process must still be running after SIGHUPs through start-up"
    );
    drop(child);
}

/// The operator's usual sequence is "write the file, then signal", and with
/// the watcher on both announce the same edit. That must be one reload, not
/// an immediate one followed by a debounced one three seconds later.
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
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let first_addr: SocketAddr = format!("127.0.0.1:{first}").parse().unwrap();
    let second_addr: SocketAddr = format!("127.0.0.1:{second}").parse().unwrap();
    wait_until(first_addr, true).await;

    std::fs::write(&config, socks_config(second)).unwrap();
    // Let the watcher deliver its event so both announcements are pending
    // together, which is the case the coalescing is for.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    sighup(&child);
    wait_until(second_addr, true).await;

    // Past the debounce: a stale event would have fired by now.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let _ = child.0.kill();
    let stdout = child.0.stdout.take().unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::BufReader::new(stdout), &mut text).unwrap();
    let restarts = text.matches("Restarting servers..").count();
    assert_eq!(restarts, 1, "one edit, one reload; stdout was:\n{text}");
    drop(child);
}
