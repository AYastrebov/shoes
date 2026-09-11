//! The process contract an operator such as awg-manager holds an engine to:
//! `check <config>`, `version`, and `SIGHUP` as an immediate reload. These
//! drive the real binary, because every claim is about `main.rs`.
//!
//! See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 1".

use std::net::SocketAddr;
use std::process::Stdio;

/// A child that dies with the test, whichever way the test ends.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn shoes_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_shoes"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let first = free_port();
    let second = free_port();
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
    // SAFETY: a plain signal to a child this test owns.
    unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) };
    wait_until(second_addr, true).await;
    wait_until(first_addr, false).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a SIGHUP reload must not wait for the 3 s file-watcher debounce"
    );
    drop(child);
}
