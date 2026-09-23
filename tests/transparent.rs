//! The transparent inbounds, driving the real binary. The test that needs a
//! real NAT rule is `#[ignore]`d and root only, because installing one is:
//!
//! ```text
//! cargo test --locked --test transparent --no-run
//! sudo target/debug/deps/transparent-<hash> --ignored
//! ```
//!
//! Building first and running the test binary under `sudo`, rather than
//! `sudo cargo test`, keeps root-owned files out of `target/`.
//!
//! See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 2".
#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The uid shoes runs as. The NAT rule excludes it, which is what keeps
/// shoes' own dial to the original destination from being diverted back
/// into shoes; it also proves the inbound does not need root.
const NOBODY: u32 = 65534;

/// A child that dies with the test, whichever way the test ends. tokio's
/// `process` feature is not enabled in this crate, so there is no
/// `kill_on_drop`; `tests/process_contract.rs` has the same guard.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An iptables rule that is removed when the test ends, pass or panic. A
/// rule left behind on a developer's machine silently diverts a port.
struct Rule(String);

impl Rule {
    fn install(rule: String) -> Self {
        run(&format!("iptables -A {rule}"));
        Self(rule)
    }
}

impl Drop for Rule {
    fn drop(&mut self) {
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("iptables -D {}", self.0))
            .status();
    }
}

fn run(cmd: &str) {
    let status = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    assert!(status.success(), "`{cmd}` failed");
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_redirect_config(dir: &Path, listener_port: u16) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("- address: 127.0.0.1:{listener_port}\n  protocol:\n    type: redirect\n"),
    )
    .unwrap();
    config
}

fn spawn_shoes(config: &Path) -> Child {
    Child(
        Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("--no-reload")
            .arg(config)
            .stdout(Stdio::null())
            // Inherited, so a bind failure is in the test's output.
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

/// shoes as `nobody`, from a copy in `dir`: `target/` usually sits under a
/// home directory `nobody` cannot traverse.
fn spawn_shoes_as_nobody(dir: &Path, config: &Path) -> Child {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let bin = dir.join("shoes");
    std::fs::copy(env!("CARGO_BIN_EXE_shoes"), &bin).unwrap();
    for (path, mode) in [(dir, 0o755), (bin.as_path(), 0o755), (config, 0o644)] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    Child(
        Command::new(&bin)
            .arg("--no-reload")
            .arg(config)
            .uid(NOBODY)
            .gid(NOBODY)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

/// Wait until `shoes` is listening on `addr`.
///
/// `free_port` released the port before shoes bound it, so something else can
/// take it in between. A listener answering there proves nothing unless shoes
/// is also still running: a shoes that lost the race has exited with a bind
/// error, and the test must say that rather than carry on against a stranger.
async fn wait_for(shoes: &mut Child, addr: SocketAddr) {
    // Fifteen seconds for the same reason as process_contract.rs: the first
    // execution of a freshly copied binary can be slow on a loaded runner.
    for _ in 0..300 {
        if let Some(status) = shoes.0.try_wait().unwrap() {
            panic!("shoes exited with {status} before listening on {addr}; its stderr is above");
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{addr} never came up");
}

/// A client that dials the listener itself was not redirected. Where
/// conntrack is loaded the kernel still reports an "original" destination for
/// it, the listener's own address, and forwarding there is shoes dialling
/// itself without end; where it is not loaded there is no destination at
/// all. Either way the connection must be closed, and neither case needs
/// root to set up.
#[tokio::test]
async fn a_direct_connection_to_a_redirect_listener_is_closed_not_looped() {
    let listener_port = free_port();
    let listener: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = write_redirect_config(dir.path(), listener_port);
    let mut shoes = spawn_shoes(&config);
    wait_for(&mut shoes, listener).await;

    let direct = async {
        let mut client = tokio::net::TcpStream::connect(listener).await.unwrap();
        let _ = client.write_all(b"hello").await;
        let mut sink = Vec::new();
        let _ = client.read_to_end(&mut sink).await;
        assert!(sink.is_empty(), "nothing may answer a direct connection");
    };
    tokio::time::timeout(Duration::from_secs(5), direct)
        .await
        .expect("a direct connection is closed, not forwarded into a loop");
}

#[tokio::test]
#[ignore = "needs root: installs an iptables NAT rule"]
async fn redirect_forwards_to_the_original_destination() {
    assert!(is_root(), "needs root for iptables");

    let listener_port = free_port();
    let listener: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = write_redirect_config(dir.path(), listener_port);
    let mut shoes = spawn_shoes_as_nobody(dir.path(), &config);
    wait_for(&mut shoes, listener).await;

    // The target answers with a prefix, so a reply proves the bytes went
    // through it rather than being echoed by something in between.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut hello = [0u8; 5];
        stream.read_exact(&mut hello).await.unwrap();
        stream.write_all(b"echo:").await.unwrap();
        stream.write_all(&hello).await.unwrap();
    });

    // The local-client shape of what awg-manager installs in PREROUTING for
    // the LAN. shoes dials the same address and port the client did; without
    // the owner match that dial is diverted too, and the connection loops.
    let _rule = Rule::install(format!(
        "OUTPUT -t nat -p tcp -d 127.0.0.1 --dport {target_port} \
         -m owner ! --uid-owner {NOBODY} -j REDIRECT --to-ports {listener_port}"
    ));

    let through_shoes = async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", target_port))
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"echo:hello");
    };
    tokio::time::timeout(Duration::from_secs(5), through_shoes)
        .await
        .expect("the redirected connection reached the target through shoes");
}
