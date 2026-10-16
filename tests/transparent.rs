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
//! Without `sudo`, a user and network namespace grants the same powers over
//! a private network stack, where your `/etc/subuid` range maps the `nobody`
//! the tests run shoes as. It needs a default route, which the namespace
//! lacks, and a `TMPDIR` not mounted `nosuid`, which would void the file
//! capability the `tproxy` test sets:
//!
//! ```text
//! unshare --map-root-user --map-auto -n sh -c '
//!   ip link set lo up
//!   ip link add d0 type dummy && ip link set d0 up
//!   ip addr add 10.9.0.1/24 dev d0 && ip route add default via 10.9.0.2
//!   TMPDIR=/var/tmp target/debug/deps/transparent-<hash> --ignored'
//! ```
//!
//! See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 2".
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

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
/// home directory `nobody` cannot traverse. With `transparent` the copy gets
/// `CAP_NET_RAW`, the narrower of the two capabilities the kernel accepts
/// for `IP_TRANSPARENT`, which also proves `tproxy` needs no more.
fn spawn_shoes_as_nobody(dir: &Path, config: &Path, transparent: bool) -> Child {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let bin = dir.join("shoes");
    std::fs::copy(env!("CARGO_BIN_EXE_shoes"), &bin).unwrap();
    for (path, mode) in [(dir, 0o755), (bin.as_path(), 0o755), (config, 0o644)] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    if transparent {
        run(&format!("setcap cap_net_raw+ep {}", bin.display()));
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
    let mut shoes = spawn_shoes_as_nobody(dir.path(), &config, false);
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

/// Commands undone when the test ends, pass or panic, in reverse order: a
/// policy route left behind on a developer's machine silently swallows
/// marked traffic.
struct Setup(Vec<String>);

impl Setup {
    fn run(&mut self, cmd: &str, undo: &str) {
        run(cmd);
        self.0.push(undo.to_string());
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        for undo in self.0.iter().rev() {
            let _ = Command::new("sh").arg("-c").arg(undo).status();
        }
    }
}

fn write_tproxy_config(dir: &Path, listener_port: u16, rules: &str) -> std::path::PathBuf {
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "- address: 127.0.0.1:{listener_port}\n  transport: udp\n  protocol:\n    \
             type: tproxy\n{rules}"
        ),
    )
    .unwrap();
    config
}

/// Wait until `shoes` has bound UDP `port`, by `/proc/net/udp`: the probe
/// awg-manager itself uses, and the only one for a socket that answers
/// nothing. Fails if shoes has exited, for the reason `wait_for` gives.
async fn wait_for_udp_bound(shoes: &mut Child, port: u16) {
    let needle = format!(":{port:04X} ");
    for _ in 0..300 {
        if let Some(status) = shoes.0.try_wait().unwrap() {
            panic!("shoes exited with {status} before binding UDP {port}; its stderr is above");
        }
        let table = std::fs::read_to_string("/proc/net/udp").unwrap_or_default();
        if table.lines().any(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|local| format!("{local} ").ends_with(&needle))
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing bound UDP port {port}");
}

/// Two round trips with `remote` through shoes, each reply spoofed from it.
/// The second is the point of two: by then a reply socket bound to the
/// remote exists, and were it connected to the client, TPROXY would hand it
/// the client's next datagram instead of the listener, and nothing reads it.
async fn exchange(client: &tokio::net::UdpSocket, remote: SocketAddr) {
    for payload in [&b"ping"[..], b"again"] {
        client.send_to(payload, remote).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
        assert_eq!(
            from, remote,
            "the reply must appear to come from the remote, not from shoes"
        );
    }
}

/// Without `CAP_NET_RAW` or `CAP_NET_ADMIN` the listener cannot be made
/// transparent, and the process must say which capability it lacks rather
/// than fail with a bare EPERM. Needs no root, which is the point.
#[test]
fn a_tproxy_listener_without_the_capability_says_so() {
    use std::io::Read;

    if is_root() {
        return; // root has the capability; the ignored test covers that side
    }
    let dir = tempfile::tempdir().unwrap();
    let config = write_tproxy_config(dir.path(), free_port(), "");
    let mut shoes = Child(
        Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("--no-reload")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // A deadline, because the failure this guards against is a listener
    // that starts after all (a regression, or a user who already holds the
    // capability), and a running server would hang the suite. Fifteen
    // seconds for the reason `wait_for` gives.
    let mut status = None;
    for _ in 0..300 {
        status = shoes.0.try_wait().unwrap();
        if status.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = status.expect("the listener started; it must refuse without the capability");
    let mut stderr = String::new();
    shoes
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("CAP_NET_RAW") && stderr.contains("CAP_NET_ADMIN"),
        "stderr: {stderr}"
    );
}

#[tokio::test]
#[ignore = "needs root: installs a policy route and an iptables TPROXY rule"]
async fn tproxy_delivers_a_datagram_and_spoofs_the_reply_source() {
    assert!(is_root(), "needs root for iptables and setcap");

    // The echo stands in for the remote. The client addresses a remote that
    // is not on this host, as a LAN client does; shoes is told by a rule to
    // dial the echo instead, and its reply must still come from the address
    // the client spoke to.
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let remote: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    // A router service on the remote's port, bound the way dnsmasq binds 53:
    // the wildcard, with SO_REUSEADDR. The reply socket's bind overlaps it,
    // and fails unless the reply socket sets SO_REUSEADDR too.
    let service = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    service.set_reuse_address(true).unwrap();
    service
        .bind(&SocketAddr::from(([0, 0, 0, 0], remote.port())).into())
        .unwrap();

    let listener_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let config = write_tproxy_config(
        dir.path(),
        listener_port,
        &format!(
            "  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n      \
             override_address: {echo_addr}\n"
        ),
    );
    let mut shoes = spawn_shoes_as_nobody(dir.path(), &config, true);
    wait_for_udp_bound(&mut shoes, listener_port).await;

    // The local-client shape of what awg-manager installs for the LAN. A
    // locally sent datagram traverses OUTPUT, not PREROUTING: mark it there,
    // and the policy route loops it through `lo` into PREROUTING, where
    // TPROXY can act. Nothing of shoes' needs excluding, as the redirect
    // test's owner match does: shoes dials the echo, never the remote.
    let mut setup = Setup(Vec::new());
    setup.run(
        "ip rule add fwmark 0x1 lookup 100 priority 30000",
        "ip rule del fwmark 0x1 lookup 100 priority 30000",
    );
    setup.run(
        "ip route add local 0.0.0.0/0 dev lo table 100",
        "ip route del local 0.0.0.0/0 dev lo table 100",
    );
    let mark = format!(
        "OUTPUT -t mangle -p udp -d {} --dport {} -j MARK --set-mark 0x1",
        remote.ip(),
        remote.port()
    );
    setup.run(
        &format!("iptables -A {mark}"),
        &format!("iptables -D {mark}"),
    );
    let tproxy = format!(
        "PREROUTING -t mangle -p udp -d {} --dport {} -j TPROXY --on-ip 127.0.0.1 \
         --on-port {listener_port} --tproxy-mark 0x1/0x1",
        remote.ip(),
        remote.port()
    );
    setup.run(
        &format!("iptables -A {tproxy}"),
        &format!("iptables -D {tproxy}"),
    );

    let through_shoes = async {
        // The wildcard, so the source is the host's own address: the kernel
        // refuses a loopback source on a route to a remote, with EINVAL.
        let client = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        exchange(&client, remote).await;
    };
    tokio::time::timeout(Duration::from_secs(5), through_shoes)
        .await
        .expect("the datagram went through shoes and came back spoofed");
}

/// A LAN client, which is what `tproxy` is for: its datagrams arrive on
/// another interface and are routed, unlike the local client above, whose
/// datagrams loop through `lo` with their route already chosen. Routing them
/// is where `src_valid_mark` bites (CONFIG.md, "Tproxy"); this follows the
/// remedy that note gives, so a host with it on runs the test too.
///
/// The client lives in a network namespace of its own, across a veth pair.
/// Its own mark, table and remote, so it can run beside the test above.
#[tokio::test]
#[ignore = "needs root: creates a network namespace, a policy route and an iptables TPROXY rule"]
async fn tproxy_relays_a_client_on_another_interface() {
    assert!(is_root(), "needs root for namespaces, iptables and setcap");

    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let remote: SocketAddr = "198.51.100.8:5353".parse().unwrap();

    let listener_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let config = write_tproxy_config(
        dir.path(),
        listener_port,
        &format!(
            "  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n      \
             override_address: {echo_addr}\n"
        ),
    );
    let mut shoes = spawn_shoes_as_nobody(dir.path(), &config, true);
    wait_for_udp_bound(&mut shoes, listener_port).await;

    // The LAN: a namespace held open by a sleeping child, which takes the
    // namespace and the veth pair with it when it dies.
    let lan = Child(
        Command::new("unshare")
            .args(["-n", "sleep", "60"])
            .spawn()
            .unwrap(),
    );
    let lan_pid = lan.0.id();
    let own = std::fs::read_link("/proc/self/ns/net").unwrap();
    for _ in 0..100 {
        if std::fs::read_link(format!("/proc/{lan_pid}/ns/net")).is_ok_and(|ns| ns != own) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let veth = format!("tpl{listener_port}");
    run(&format!(
        "ip link add {veth} type veth peer name eth0 netns {lan_pid} && \
         ip addr add 192.0.2.1/24 dev {veth} && ip link set {veth} up"
    ));
    run(&format!(
        "nsenter -t {lan_pid} -n sh -c 'ip link set lo up && \
         ip addr add 192.0.2.2/24 dev eth0 && ip link set eth0 up && \
         ip route add default via 192.0.2.1'"
    ));
    let src_valid_mark = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/src_valid_mark")
        .is_ok_and(|v| v.trim() == "1");
    if src_valid_mark {
        // Per interface, so it goes with the veth.
        run(&format!("sysctl -qw net.ipv4.conf.{veth}.accept_local=1"));
    }

    let mut setup = Setup(Vec::new());
    setup.run(
        "ip rule add fwmark 0x2 lookup 101 priority 30001",
        "ip rule del fwmark 0x2 lookup 101 priority 30001",
    );
    setup.run(
        "ip route add local 0.0.0.0/0 dev lo table 101",
        "ip route del local 0.0.0.0/0 dev lo table 101",
    );
    let tproxy = format!(
        "PREROUTING -t mangle -i {veth} -p udp -d {} --dport {} -j TPROXY --on-ip 127.0.0.1 \
         --on-port {listener_port} --tproxy-mark 0x2/0x2",
        remote.ip(),
        remote.port()
    );
    setup.run(
        &format!("iptables -A {tproxy}"),
        &format!("iptables -D {tproxy}"),
    );

    // A socket keeps the namespace it was made in, so make it on a thread
    // that has entered the LAN's, and use it from here.
    let client = std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        let ns = std::fs::File::open(format!("/proc/{lan_pid}/ns/net")).unwrap();
        assert_eq!(
            // SAFETY: a valid namespace descriptor; only this thread moves.
            unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) },
            0,
            "setns: {}",
            std::io::Error::last_os_error()
        );
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    })
    .join()
    .unwrap();
    let client = tokio::net::UdpSocket::from_std(client).unwrap();

    let through_shoes = async {
        exchange(&client, remote).await;
    };
    tokio::time::timeout(Duration::from_secs(5), through_shoes)
        .await
        .expect("the LAN client's datagram went through shoes and came back spoofed");
    drop(lan);
}
