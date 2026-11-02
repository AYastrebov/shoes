//! The tunnel runtime against an in-process Phobos server double.
//!
//! The double is what a Phobos deployment looks like from the client: a UDP
//! socket running the obfuscator (a server-side `PhobosCodec`), in front of
//! a plain WireGuard peer (`Tunn::new`). It stands in for the reference
//! server, which forwards to kernel WireGuard; the codec on both sides is
//! awgtun's, whose wire format is checked against the reference's own
//! vectors and decoder there.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use awgtun::amnezia::Amnezia3Config;
use awgtun::noise::{Tunn, TunnResult};
use awgtun::phobos::{Masking, PhobosCodec, PhobosConfig, Unwrapped};
use awgtun::x25519;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::TunnelRuntime;

/// What the double saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seen {
    /// A raw STUN Binding Request from the client.
    BindingRequest,
    /// A raw STUN Binding Success from the client: its answer to ours.
    BindingSuccess,
    /// A WireGuard message decoded from `from`, by its type field.
    Message { from: SocketAddr, msg_type: u32 },
    /// A tunnel packet the server's WireGuard decrypted.
    Delivered(Vec<u8>),
    /// A datagram the server's WireGuard refused once decoded.
    Rejected,
    /// A datagram that was neither control traffic nor decodable.
    Undecodable,
}

pub(crate) fn keypair(seed: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
    let secret = x25519::StaticSecret::from([seed; 32]);
    let public = x25519::PublicKey::from(&secret);
    (secret, public)
}

fn phobos(key: &[u8], masking: Masking) -> PhobosConfig {
    let mut config = PhobosConfig::new(key.to_vec()).unwrap();
    config.masking = masking;
    config
}

/// A minimal IPv4/UDP packet from the tunnel address, so the server's
/// WireGuard has something routable to deliver.
pub(crate) fn ip_packet(payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&Ipv4Addr::new(10, 8, 0, 2).octets());
    p[16..20].copy_from_slice(&Ipv4Addr::new(10, 8, 0, 1).octets());
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

/// The double: answers like a Phobos server in front of WireGuard, and
/// reports everything it sees. With `ask_binding`, it sends the client one
/// Binding Request once the handshake completes, as the server's control
/// timer does.
pub(crate) async fn spawn_double(
    config: PhobosConfig,
    ask_binding: bool,
) -> (SocketAddr, mpsc::UnboundedReceiver<Seen>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let (server_secret, _) = keypair(2);
    let (_, client_public) = keypair(1);
    let mut server = Tunn::new(server_secret, client_public, None, None, 7, None);
    let mut codec = PhobosCodec::new(config).unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut out = vec![0u8; 65536];
        let mut wire = Vec::new();
        let mut asked = false;
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            // Control traffic is raw STUN: classify before unwrapping.
            let mut control = false;
            if n >= 8 && buf[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                match u16::from_be_bytes([buf[0], buf[1]]) {
                    0x0001 => {
                        control = true;
                        let _ = tx.send(Seen::BindingRequest);
                    }
                    0x0101 => {
                        control = true;
                        let _ = tx.send(Seen::BindingSuccess);
                    }
                    _ => {}
                }
            }
            let message = match codec.unwrap(&mut buf[..n], from) {
                Unwrapped::WireGuard(message) => message.to_vec(),
                Unwrapped::Reply(reply) => {
                    let _ = socket.send_to(&reply, from).await;
                    continue;
                }
                Unwrapped::Drop => {
                    if !control {
                        let _ = tx.send(Seen::Undecodable);
                    }
                    continue;
                }
            };
            let msg_type = u32::from_le_bytes(message[..4].try_into().unwrap());
            let _ = tx.send(Seen::Message { from, msg_type });

            let mut input: &[u8] = &message;
            loop {
                match server.decapsulate(Some(from.ip()), input, &mut out) {
                    TunnResult::WriteToNetwork(reply) => {
                        codec.wrap(reply, &mut wire).unwrap();
                        let _ = socket.send_to(&wire, from).await;
                        if ask_binding && !asked {
                            asked = true;
                            let request = codec.binding_request();
                            let _ = socket.send_to(&request, from).await;
                        }
                    }
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        let _ = tx.send(Seen::Delivered(packet.to_vec()));
                        break;
                    }
                    TunnResult::Err(_) => {
                        let _ = tx.send(Seen::Rejected);
                        break;
                    }
                    _ => break,
                }
                // Drain what the call queued, per decapsulate's contract.
                input = &[];
            }
        }
    });
    (addr, rx)
}

async fn start_client(server: SocketAddr, config: PhobosConfig) -> Arc<TunnelRuntime> {
    let (client_secret, _) = keypair(1);
    let (_, server_public) = keypair(2);
    let mut amnezia = Amnezia3Config::default();
    amnezia.mtu = 1280;
    TunnelRuntime::start(
        client_secret,
        server_public,
        None,
        None,
        amnezia,
        server,
        Some(config),
    )
    .await
    .unwrap()
}

/// Wait for the first event matching `want`, returning everything seen up
/// to and including it. Bounded: an in-process exchange takes milliseconds.
pub(crate) async fn until(
    rx: &mut mpsc::UnboundedReceiver<Seen>,
    want: impl Fn(&Seen) -> bool,
) -> Vec<Seen> {
    let mut seen = Vec::new();
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = rx.recv().await {
            let done = want(&event);
            seen.push(event);
            if done {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(found, "never saw the expected event; saw {seen:?}");
    seen
}

/// An IP packet offered to the tunnel reaches the server's WireGuard,
/// through a wrapped handshake, under every masking.
#[tokio::test]
async fn a_packet_crosses_a_phobos_server_under_every_masking() {
    for masking in [Masking::None, Masking::Stun, Masking::Media] {
        let config = phobos(b"synthetic-preset-key", masking);
        let (server, mut seen) = spawn_double(config.clone(), false).await;
        let runtime = start_client(server, config).await;

        let packet = ip_packet(b"over phobos");
        runtime.ip_to_tunnel_tx.send(packet.clone()).await.unwrap();

        let events = until(&mut seen, |e| matches!(e, Seen::Delivered(_))).await;
        assert_eq!(events.last(), Some(&Seen::Delivered(packet)), "{masking:?}");
        let initiation = events
            .iter()
            .position(|e| matches!(e, Seen::Message { msg_type: 1, .. }))
            .expect("a handshake initiation decoded");
        // Under a masking with control traffic, a Binding Request goes
        // ahead of the initiation, as the reference sends it.
        let request = events.iter().position(|e| *e == Seen::BindingRequest);
        match masking {
            Masking::None => assert_eq!(request, None, "{events:?}"),
            _ => assert!(request.is_some_and(|r| r < initiation), "{events:?}"),
        }
        assert!(!events.contains(&Seen::Rejected), "{masking:?}: {events:?}");
        drop(runtime);
    }
}

/// The negative control: a client with a different key reaches the double,
/// and nothing it sends decodes into a handshake the server's WireGuard
/// accepts. Without this, a layer that silently did nothing would pass the
/// test above, since a plain WireGuard double would also handshake.
#[tokio::test]
async fn a_client_with_the_wrong_key_is_not_understood() {
    let (server, mut seen) = spawn_double(phobos(b"server-key", Masking::Stun), false).await;
    let runtime = start_client(server, phobos(b"client-key", Masking::Stun)).await;
    runtime.ip_to_tunnel_tx.send(ip_packet(b"x")).await.unwrap();

    // The initiation is sent at once. Whatever the double makes of it, it
    // must end as garbage: undecodable, or decoded into something the
    // server's WireGuard refuses.
    let events = until(&mut seen, |e| {
        matches!(e, Seen::Rejected | Seen::Undecodable | Seen::Delivered(_))
    })
    .await;
    assert!(
        matches!(events.last(), Some(Seen::Rejected | Seen::Undecodable)),
        "{events:?}"
    );
    drop(runtime);
}

/// A Binding Request from the server is answered, and the answer never
/// reaches the receive loop as a WireGuard message.
#[tokio::test]
async fn a_binding_request_from_the_server_is_answered() {
    let config = phobos(b"synthetic-preset-key", Masking::Stun);
    let (server, mut seen) = spawn_double(config.clone(), true).await;
    let runtime = start_client(server, config).await;
    runtime
        .ip_to_tunnel_tx
        .send(ip_packet(b"ping"))
        .await
        .unwrap();

    until(&mut seen, |e| *e == Seen::BindingSuccess).await;
    drop(runtime);
}

/// After a rebind, the first message from the new address is a handshake
/// initiation, even with a live session: a Phobos server drops everything
/// else from an address it has not seen complete a handshake.
#[tokio::test]
async fn a_rebind_behind_phobos_starts_with_a_handshake() {
    let config = phobos(b"synthetic-preset-key", Masking::Stun);
    let (server, mut seen) = spawn_double(config.clone(), false).await;
    let runtime = start_client(server, config).await;

    runtime
        .ip_to_tunnel_tx
        .send(ip_packet(b"before"))
        .await
        .unwrap();
    let before = until(&mut seen, |e| matches!(e, Seen::Delivered(_))).await;
    let old_from = before
        .iter()
        .find_map(|e| match e {
            Seen::Message { from, .. } => Some(*from),
            _ => None,
        })
        .unwrap();

    {
        use crate::network_change::NetworkChangeListener;
        runtime.endpoint.network_changed();
    }

    let after = until(
        &mut seen,
        |e| matches!(e, Seen::Message { from, .. } if *from != old_from),
    )
    .await;
    assert_eq!(
        after.last().map(|e| match e {
            Seen::Message { msg_type, .. } => *msg_type,
            _ => 0,
        }),
        Some(1),
        "the first message from the new address must be an initiation: {after:?}"
    );

    // And the tunnel carries traffic again over the new path.
    let packet = ip_packet(b"after");
    runtime.ip_to_tunnel_tx.send(packet.clone()).await.unwrap();
    let events = until(&mut seen, |e| matches!(e, Seen::Delivered(_))).await;
    assert_eq!(events.last(), Some(&Seen::Delivered(packet)));
    drop(runtime);
}
