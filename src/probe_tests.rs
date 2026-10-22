//! What shoes' servers show a client that is not one (spec:
//! `docs/specs/2026-10-22-probe-harness.md`).
//!
//! Every server here runs in-process on a real loopback socket, started by
//! `start_servers` as production starts it. Each probe ends as data, a close
//! or silence, judged from the bytes and the close the prober's own socket
//! saw, with a time bound and never by error text. The matrix pins today's
//! outcome and names the audit finding wherever that differs from what the
//! references do, so a Phase 2 fix changes a cell on purpose.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a failed setup is a failed test"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream, SocketPassthrough};
use crate::config::ClientProxyConfig;
use crate::connections::ConnectionSet;
use crate::quic_outbound::testing::{generate_certificate, reserve_tcp_port, test_resolver};
use crate::tcp::tcp_client_handler_factory::{HopContext, create_tcp_client_handler};

/// A close this soon after the probe's last write is "at once".
const AT_ONCE: Duration = Duration::from_secs(1);
/// How long a probe watches. Far under the 60 s setup deadline, and long
/// enough that a server closing after reading what it needs has done so.
const BOUND: Duration = Duration::from_secs(2);

/// What a probe saw, as the spec's three outcomes. A close after `AT_ONCE`
/// but within the bound is told apart, since "closes at once" is the
/// fingerprint the audit names (theme 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Outcome {
    /// The server sent bytes.
    Data,
    /// It closed, by FIN or reset, without sending anything, at once.
    ClosedAtOnce,
    /// It closed without sending anything, after `AT_ONCE`.
    ClosedLater,
    /// Neither, for the whole bound.
    Silent,
}

#[derive(Debug, Default)]
struct Log {
    received: usize,
    /// The first bytes received, enough to tell the decoy's answer.
    first: Vec<u8>,
    closed_at: Option<Instant>,
    last_write: Option<Instant>,
}

impl Log {
    fn closed(&mut self) {
        self.closed_at.get_or_insert_with(Instant::now);
    }

    fn concluded(&self) -> bool {
        self.received > 0 || self.closed_at.is_some()
    }
}

/// The prober's socket, recording what the server sent and when it closed.
/// A client handler reads through it, so a wrong-key probe made by shoes'
/// own client is judged by the same bytes as a raw one.
struct Tap {
    inner: TcpStream,
    log: Arc<Mutex<Log>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let mut log = self.log.lock().unwrap();
        match &poll {
            Poll::Ready(Ok(())) if buf.filled().len() > before => {
                log.received += buf.filled().len() - before;
                let room = 16usize.saturating_sub(log.first.len());
                let new = &buf.filled()[before..];
                log.first.extend_from_slice(&new[..room.min(new.len())]);
            }
            Poll::Ready(_) => log.closed(),
            Poll::Pending => {}
        }
        poll
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        match &poll {
            Poll::Ready(Ok(n)) if *n > 0 => {
                self.log.lock().unwrap().last_write = Some(Instant::now());
            }
            // A reset can surface on a write before any read sees it.
            Poll::Ready(Err(_)) => self.log.lock().unwrap().closed(),
            _ => {}
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(poll, Poll::Ready(Err(_))) {
            self.log.lock().unwrap().closed();
        }
        poll
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for Tap {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

/// No passthrough: the tap has to see every byte the server sends.
impl SocketPassthrough for Tap {}

impl AsyncStream for Tap {}

/// A probe's outcome and the first bytes the server sent.
pub(crate) struct Seen {
    pub(crate) outcome: Outcome,
    pub(crate) first: Vec<u8>,
}

fn seen(log: &Log, started: Instant) -> Seen {
    Seen {
        outcome: judge(log, started),
        first: log.first.clone(),
    }
}

fn judge(log: &Log, started: Instant) -> Outcome {
    if log.received > 0 {
        return Outcome::Data;
    }
    match log.closed_at {
        Some(closed) => {
            let from = log.last_write.unwrap_or(started);
            if closed.saturating_duration_since(from) <= AT_ONCE {
                Outcome::ClosedAtOnce
            } else {
                Outcome::ClosedLater
            }
        }
        None => Outcome::Silent,
    }
}

/// A tapped connection to `addr`, and a second handle to the same socket.
/// A client that errors drops its tap; the second handle keeps the
/// connection open so the probe can go on watching it.
async fn tap(addr: SocketAddr) -> (Tap, TcpStream, Arc<Mutex<Log>>) {
    let inner = TcpStream::connect(addr).await.unwrap().into_std().unwrap();
    let observer = TcpStream::from_std(inner.try_clone().unwrap()).unwrap();
    let inner = TcpStream::from_std(inner).unwrap();
    let log = Arc::new(Mutex::new(Log::default()));
    (
        Tap {
            inner,
            log: log.clone(),
        },
        observer,
        log,
    )
}

/// Read `socket` until the server sends, closes, or `deadline`, unless the
/// log already says which.
async fn watch(socket: &mut TcpStream, log: &Mutex<Log>, deadline: tokio::time::Instant) {
    if log.lock().unwrap().concluded() {
        return;
    }
    let mut buf = [0u8; 4096];
    match tokio::time::timeout_at(deadline, socket.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let mut log = log.lock().unwrap();
            log.received += n;
            log.first.extend_from_slice(&buf[..n.min(16)]);
        }
        Ok(_) => log.lock().unwrap().closed(),
        Err(_) => {}
    }
}

/// Send `bytes`, then read until the server sends, closes, or the bound.
pub(crate) async fn probe_raw(addr: SocketAddr, bytes: &[u8]) -> Seen {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + BOUND;
    let (mut tap, mut observer, log) = tap(addr).await;
    // A write the server already refused is a close, which the tap records.
    let _ = tap.write_all(bytes).await;
    let _ = tap.flush().await;
    watch(&mut observer, &log, deadline).await;
    seen(&log.lock().unwrap(), started)
}

/// Open a connection through shoes' own client for `client` (YAML), then
/// send one request through it and wait as `probe_raw` does. The outcome is
/// judged on the socket underneath.
pub(crate) async fn probe_client(addr: SocketAddr, client: &str) -> Seen {
    let started = Instant::now();
    let config: ClientProxyConfig = serde_yaml::from_str(client).unwrap();
    let server = NetLocation::from_ip_addr(addr.ip(), addr.port());
    let handler =
        create_tcp_client_handler(config, None, &HopContext::new(&server), test_resolver());
    let (tap, mut observer, log) = tap(addr).await;
    let deadline = tokio::time::Instant::now() + BOUND;
    let target = NetLocation::from_str("192.0.2.1:80", None).unwrap();
    let _ = tokio::time::timeout_at(deadline, async {
        let Ok(setup) = handler
            .setup_client_tcp_stream(Box::new(tap), target.into())
            .await
        else {
            return;
        };
        let mut stream = setup.client_stream;
        if stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .is_err()
            || stream.flush().await.is_err()
        {
            return;
        }
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
    })
    .await;
    // However the client ended, the verdict is the socket's: a client error
    // is not the server closing, and a reset it consumed is in the log.
    watch(&mut observer, &log, deadline).await;
    seen(&log.lock().unwrap(), started)
}

/// A stand-in for a real site: answers `decoy\n` to the first bytes it gets.
/// REALITY's `dest` and ShadowTLS's handshake server point here, so a probe
/// they relay comes back as data.
pub(crate) async fn spawn_decoy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                if matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {
                    let _ = socket.write_all(b"decoy\n").await;
                }
                let _ = socket.read(&mut buf).await;
            });
        }
    });
    addr
}

/// Start every server in `yaml` (a full config) the way the binary does.
/// The servers live as long as the returned set.
pub(crate) async fn start(yaml: &str) -> ConnectionSet {
    let configs = crate::config::load_config_str(yaml).unwrap();
    let validated = crate::config::create_server_configs(configs).unwrap();
    let connections = ConnectionSet::new();
    for config in validated.configs {
        crate::tcp::tcp_server::start_servers(config, test_resolver(), &connections)
            .await
            .unwrap();
    }
    connections
}

/// A deterministic byte string: the same probe on every run.
fn seeded(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Probe {
    ForeignHello,
    HttpGet,
    Short,
    Random,
    WrongKey,
}

impl Probe {
    const ALL: [Probe; 5] = [
        Probe::ForeignHello,
        Probe::HttpGet,
        Probe::Short,
        Probe::Random,
        Probe::WrongKey,
    ];

    fn bytes(self) -> Vec<u8> {
        match self {
            // A real ClientHello for www.example.com, which no server here
            // is configured for: sing-box's REALITY hello from #95.
            Probe::ForeignHello => crate::kat::hex(&crate::kat::vectors("reality")["client_hello"]),
            Probe::HttpGet => b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            // Under every header; VL-V1 is a 17-byte peek.
            Probe::Short => seeded(16, 0x5eed_0001),
            // More than any header or drain.
            Probe::Random => seeded(4096, 0x5eed_0002),
            Probe::WrongKey => unreachable!("made by a client"),
        }
    }
}

/// Which reference family a cell's outcome matches (spec, "What the
/// references do"), or the audit finding that covers a cell matching none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// sing-box or a sing library behaves the same.
    Sing,
    /// Xray, or the protocol's own reference server, behaves the same.
    Xray,
    /// Both families behave the same way here.
    Both,
    /// The server relays to a real site, as REALITY and ShadowTLS must.
    Relay,
    /// A plain proxy protocol (SOCKS5, HTTP), answering as its RFC says.
    /// These are not hidden services, so no reference family applies.
    Protocol,
    /// No reference behaves this way; the audit id says where it is recorded.
    Finding(&'static str),
}

struct Server {
    name: &'static str,
    /// The listener, with `{port}` and `{decoy}` filled in.
    config: &'static str,
    /// The wrong-key client, `{port}` filled in.
    wrong_key: &'static str,
}

const SS_KEY_2022: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

const SERVERS: &[Server] = &[
    Server {
        name: "shadowsocks",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: shadowsocks, cipher: aes-256-gcm, password: probe-password}
"#,
        wrong_key: "{type: shadowsocks, cipher: aes-256-gcm, password: not-the-password}",
    },
    Server {
        name: "shadowsocks-2022",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: shadowsocks, cipher: 2022-blake3-aes-256-gcm, password: "{ss2022}"}
"#,
        wrong_key: r#"{type: shadowsocks, cipher: 2022-blake3-aes-256-gcm, password: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}"#,
    },
    Server {
        name: "vmess",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: vmess, cipher: aes-128-gcm, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}
"#,
        wrong_key: "{type: vmess, cipher: aes-128-gcm, user_id: 0b1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d}",
    },
    Server {
        name: "vless",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: vless, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}
"#,
        wrong_key: "{type: vless, user_id: 0b1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d}",
    },
    Server {
        name: "trojan",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: trojan, password: probe-password}
"#,
        wrong_key: "{type: trojan, password: not-the-password}",
    },
    Server {
        name: "snell",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: snell, cipher: aes-128-gcm, password: probe-password}
"#,
        wrong_key: "{type: snell, cipher: aes-128-gcm, password: not-the-password}",
    },
    Server {
        name: "socks",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: socks, username: probe, password: probe-password}
"#,
        wrong_key: "{type: socks, username: probe, password: not-the-password}",
    },
    Server {
        name: "http",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol: {type: http, username: probe, password: probe-password}
"#,
        wrong_key: "{type: http, username: probe, password: not-the-password}",
    },
    Server {
        name: "vless-in-tls",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol:
    type: tls
    tls_targets:
      localhost:
        cert: "{cert}"
        key: "{key}"
        protocol: {type: vless, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}
"#,
        wrong_key: r#"
type: tls
verify: false
sni_hostname: localhost
protocol: {type: vless, user_id: 0b1f2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d}
"#,
    },
    Server {
        name: "reality",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol:
    type: tls
    reality_targets:
      reality.test:
        private_key: QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI
        short_ids: ["0123456789abcdef"]
        dest: "127.0.0.1:{decoy}"
        protocol: {type: vless, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}
"#,
        // The server's name and short id, the wrong public key: the
        // REALITY auth fails.
        wrong_key: r#"
type: reality
public_key: ERERERERERERERERERERERERERERERERERERERERERE
short_id: "0123456789abcdef"
sni_hostname: reality.test
protocol: {type: vless, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}
"#,
    },
    Server {
        name: "shadowtls",
        config: r#"
- address: "127.0.0.1:{port}"
  protocol:
    type: tls
    shadowtls_targets:
      shadowtls.test:
        password: probe-password
        handshake:
          address: "127.0.0.1:{decoy}"
        protocol: {type: socks}
"#,
        wrong_key: r#"
type: shadowtls
password: not-the-password
sni_hostname: shadowtls.test
protocol: {type: socks}
"#,
    },
];

/// Today's outcome for each (server, probe), and what it matches (spec,
/// "What the references do"). Where a cell matches neither family, the
/// finding says where it is recorded: the audit's XF-1 group, or this
/// harness's own PH ids in the spec.
fn expected() -> BTreeMap<(&'static str, Probe), (Outcome, Verdict)> {
    use Outcome::*;
    use Probe::*;
    use Verdict::*;
    let cells: &[(&str, [(Outcome, Verdict); 5])] = &[
        // Order: ForeignHello, HttpGet, Short, Random, WrongKey.
        //
        // AEAD waits for salt + 18 bytes with no timeout, then resets: sing.
        (
            "shadowsocks",
            [
                (ClosedAtOnce, Sing),
                (Silent, Sing),
                (Silent, Sing),
                (ClosedAtOnce, Sing),
                (ClosedAtOnce, Sing),
            ],
        ),
        // sing resets anything under salt + 27 bytes at once; shoes waits for
        // the rest, as shadowsocks-rust does.
        (
            "shadowsocks-2022",
            [
                (ClosedAtOnce, Both),
                (Silent, Xray),
                (Silent, Xray),
                (ClosedAtOnce, Both),
                (ClosedAtOnce, Both),
            ],
        ),
        // Closes on a 16-byte auth id it does not know, as sing-vmess does;
        // Xray drains (VM-D6).
        (
            "vmess",
            [
                (ClosedAtOnce, Sing),
                (ClosedAtOnce, Sing),
                (ClosedAtOnce, Sing),
                (ClosedAtOnce, Sing),
                (ClosedAtOnce, Sing),
            ],
        ),
        // A version byte other than 0 closes at once, as in Xray without a
        // fallback; sing-box reads the whole header first.
        (
            "vless",
            [
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Both),
            ],
        ),
        // Both references judge the first read: under 56 bytes is refused at
        // once. shoes waits for 56 (PH-1).
        (
            "trojan",
            [
                (ClosedAtOnce, Both),
                (ClosedAtOnce, Both),
                (Silent, Finding("PH-1")),
                (ClosedAtOnce, Both),
                (ClosedAtOnce, Both),
            ],
        ),
        // open-snell closes on a failed open and hangs on a short header.
        (
            "snell",
            [
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Xray),
                (Silent, Xray),
                (ClosedAtOnce, Xray),
                (ClosedAtOnce, Xray),
            ],
        ),
        // A wrong password gets RFC 1929's failure reply.
        (
            "socks",
            [
                (ClosedAtOnce, Protocol),
                (ClosedAtOnce, Protocol),
                (ClosedAtOnce, Protocol),
                (ClosedAtOnce, Protocol),
                (Data, Protocol),
            ],
        ),
        // A wrong password gets 407. An origin-form request gets no answer
        // at all (PH-3).
        (
            "http",
            [
                (ClosedAtOnce, Protocol),
                (ClosedAtOnce, Finding("PH-3")),
                (Silent, Protocol),
                (ClosedAtOnce, Protocol),
                (Data, Protocol),
            ],
        ),
        // Non-TLS bytes fail the handshake with no alert, as Go's does. An
        // unknown name is refused; Go serves its certificate (PH-2).
        (
            "vless-in-tls",
            [
                (ClosedAtOnce, Finding("PH-2")),
                (ClosedAtOnce, Both),
                (ClosedAtOnce, Both),
                (ClosedAtOnce, Both),
                (Data, Both),
            ],
        ),
        // REALITY relays non-TLS bytes and unknown names to dest; shoes
        // closes (RE-R1, PH-2). A failed auth is relayed.
        (
            "reality",
            [
                (ClosedAtOnce, Finding("PH-2")),
                (ClosedAtOnce, Finding("RE-R1")),
                (ClosedAtOnce, Finding("RE-R1")),
                (ClosedAtOnce, Finding("RE-R1")),
                (Data, Relay),
            ],
        ),
        // ShadowTLS waits for the record its header announces and relays a
        // failed HMAC; shoes closes on anything malformed (ST-S2, PH-2).
        (
            "shadowtls",
            [
                (ClosedAtOnce, Finding("PH-2")),
                (ClosedAtOnce, Finding("ST-S2")),
                (ClosedAtOnce, Finding("ST-S2")),
                (ClosedAtOnce, Finding("ST-S2")),
                (Data, Relay),
            ],
        ),
    ];
    let mut table = BTreeMap::new();
    for (server, row) in cells {
        let name = SERVERS.iter().find(|s| s.name == *server).unwrap().name;
        for (probe, cell) in [ForeignHello, HttpGet, Short, Random, WrongKey]
            .into_iter()
            .zip(row)
        {
            table.insert((name, probe), *cell);
        }
    }
    table
}

#[test]
fn the_table_covers_every_server_and_every_finding_is_recorded() {
    let table = expected();
    assert_eq!(table.len(), SERVERS.len() * Probe::ALL.len());
    let root = env!("CARGO_MANIFEST_DIR");
    let audit = std::fs::read_to_string(format!(
        "{root}/docs/audits/2026-10-15-quality-and-correctness-audit.md"
    ))
    .unwrap();
    let spec =
        std::fs::read_to_string(format!("{root}/docs/specs/2026-10-22-probe-harness.md")).unwrap();
    for (key, (_, verdict)) in &table {
        if let Verdict::Finding(id) = verdict {
            assert!(
                audit.contains(id) || spec.contains(&format!("**{id}**")),
                "{key:?} names {id}, which neither the audit nor the spec records"
            );
        }
    }
}

async fn observe(
    server: &'static Server,
    addr: SocketAddr,
    probe: Probe,
) -> ((&'static str, Probe), Seen) {
    let seen = match probe {
        Probe::WrongKey => probe_client(addr, server.wrong_key).await,
        _ => probe_raw(addr, &probe.bytes()).await,
    };
    ((server.name, probe), seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_server_answers_every_probe_as_recorded() {
    let decoy = spawn_decoy().await;
    // Inline PEM in a double-quoted YAML string; only the file loader reads
    // certificate paths.
    let cert = generate_certificate();
    let inline = |pem: &str| pem.replace('\n', "\\n");

    let mut yaml = String::new();
    let mut addrs = Vec::new();
    for server in SERVERS {
        let port = reserve_tcp_port().port();
        yaml.push_str(
            &server
                .config
                .replace("{port}", &port.to_string())
                .replace("{decoy}", &decoy.port().to_string())
                .replace("{ss2022}", SS_KEY_2022)
                .replace("{cert}", &inline(&cert.cert_pem))
                .replace("{key}", &inline(&cert.key_pem)),
        );
        addrs.push((server, SocketAddr::from(([127, 0, 0, 1], port))));
    }
    let _servers = start(&yaml).await;

    let started = Instant::now();
    let mut cells = Vec::new();
    for (server, addr) in &addrs {
        for probe in Probe::ALL {
            cells.push(tokio::spawn(observe(server, *addr, probe)));
        }
    }
    let mut observed = BTreeMap::new();
    let mut first_bytes = BTreeMap::new();
    for cell in cells {
        let (key, seen) = cell.await.unwrap();
        observed.insert(key, seen.outcome);
        first_bytes.insert(key, seen.first);
    }
    let elapsed = started.elapsed();

    let expected = expected();
    let mismatches: Vec<String> = observed
        .iter()
        .filter(|(key, outcome)| expected.get(key).map(|(o, _)| o) != Some(outcome))
        .map(|((server, probe), outcome)| {
            format!(
                "(\"{server}\", Probe::{probe:?}) => Outcome::{outcome:?} (expected {:?})",
                expected.get(&(server, *probe)).map(|(o, _)| *o)
            )
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} cells differ:\n{}",
        mismatches.len(),
        observed.len(),
        mismatches.join("\n")
    );
    // A relay is the point of REALITY and ShadowTLS: where they relay, the
    // prober must get the site's own answer, not shoes'.
    for (key, (outcome, verdict)) in &expected {
        if *verdict == Verdict::Relay {
            assert_eq!(*outcome, Outcome::Data, "{key:?}: a relay cell is data");
            assert!(
                first_bytes[key].starts_with(b"decoy"),
                "{key:?}: relayed {:?}, not the decoy's answer",
                first_bytes[key]
            );
        }
    }
    assert!(
        elapsed < BOUND * 3,
        "the matrix took {elapsed:?}; its cells should run concurrently"
    );
}

/// The classifier, against a listener that does each thing on purpose.
#[tokio::test]
async fn the_classifier_tells_data_a_close_a_reset_a_late_close_and_silence_apart() {
    async fn listener(behaviour: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
            match behaviour {
                "data" => {
                    socket.write_all(b"hello").await.unwrap();
                    std::future::pending::<()>().await;
                }
                "close" => drop(socket),
                "reset" => {
                    socket2::SockRef::from(&socket)
                        .set_linger(Some(Duration::ZERO))
                        .unwrap();
                    drop(socket);
                }
                "late" => {
                    tokio::time::sleep(AT_ONCE + Duration::from_millis(300)).await;
                    drop(socket);
                }
                _ => std::future::pending::<()>().await,
            }
        });
        addr
    }

    let cases = [
        ("data", Outcome::Data),
        ("close", Outcome::ClosedAtOnce),
        ("reset", Outcome::ClosedAtOnce),
        ("late", Outcome::ClosedLater),
        ("silent", Outcome::Silent),
    ]
    .map(|(behaviour, expected)| {
        tokio::spawn(async move {
            let seen = probe_raw(listener(behaviour).await, b"probe").await;
            (behaviour, seen.outcome, expected)
        })
    });
    for case in cases {
        let (behaviour, outcome, expected) = case.await.unwrap();
        assert_eq!(outcome, expected, "{behaviour}");
    }
}

/// SF-10's slow drip: one byte every 5 s, each gap shorter than any
/// per-read timeout, together longer than the 60 s setup deadline. The
/// connection must outlive the gaps and still end at the deadline, so the
/// deadline is one deadline and a drip cannot extend it.
#[tokio::test(start_paused = true)]
async fn a_slow_drip_is_held_to_the_setup_deadline_and_no_shorter() {
    use crate::async_stream::testing::TestStream;
    use crate::config::{RuleConfig, ServerProxyConfig};
    use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
    use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

    let resolver = test_resolver();
    let rules: Vec<RuleConfig> =
        serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap();
    let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
    let config: ServerProxyConfig =
        serde_yaml::from_str("{type: shadowsocks, cipher: aes-256-gcm, password: probe-password}")
            .unwrap();
    let handler: Arc<dyn crate::tcp::tcp_handler::TcpServerHandler> =
        create_tcp_server_handler(config, &selector, &resolver, None).into();

    let (near, mut far) = tokio::io::duplex(1 << 16);
    let started = tokio::time::Instant::now();
    let server = tokio::spawn(crate::tcp::tcp_server::process_stream(
        TestStream(near),
        handler,
        resolver,
        None,
    ));

    // Eleven bytes by 55 s: never the 50-byte header the cipher needs.
    for _ in 0..11 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        far.write_all(&[0x42]).await.unwrap();
        assert!(!server.is_finished(), "closed at {:?}", started.elapsed());
    }

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        server.is_finished(),
        "still open at {:?}",
        started.elapsed()
    );
    let err = server.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

async fn resetting_listener() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            socket2::SockRef::from(&socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(socket);
        }
    });
    addr
}

/// A reset can reach the prober only as a failed write. That alone is a
/// close, with no read to see it.
#[tokio::test]
async fn a_write_the_server_refused_is_a_close() {
    let started = Instant::now();
    let (mut tap, _observer, log) = tap(resetting_listener().await).await;
    let mut refused = false;
    for _ in 0..50 {
        if tap.write_all(&[0u8; 1024]).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(refused, "the reset never reached a write");
    assert_eq!(
        seen(&log.lock().unwrap(), started).outcome,
        Outcome::ClosedAtOnce
    );
}

/// A client that errors drops its tap before reading. The probe's second
/// handle keeps the socket, so the verdict is still the server's.
#[tokio::test]
async fn a_probe_outlives_a_client_that_gave_up() {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + BOUND;
    let (tap, mut observer, log) = tap(resetting_listener().await).await;
    drop(tap);
    watch(&mut observer, &log, deadline).await;
    assert_eq!(
        seen(&log.lock().unwrap(), started).outcome,
        Outcome::ClosedAtOnce
    );
}

/// End to end: shoes' own client against a server that resets at once.
#[tokio::test]
async fn a_client_against_a_resetting_server_sees_a_close() {
    let addr = resetting_listener().await;
    let seen = probe_client(
        addr,
        "{type: vless, user_id: b831381d-6324-4d53-ad4f-8cda48b30811}",
    )
    .await;
    assert_eq!(seen.outcome, Outcome::ClosedAtOnce);
}
