//! A shoes client and server complete a REALITY handshake in memory, then each is fed the
//! post-handshake handshake messages a peer may send (RFC 8446 §4.6).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::io;

use aws_lc_rs::agreement;

use super::reality_client_connection::{RealityClientConfig, RealityClientConnection};
use super::reality_server_connection::{RealityServerConfig, RealityServerConnection};
use crate::address::{Address, NetLocation};

const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn handshaken_pair() -> (RealityClientConnection, RealityServerConnection) {
    let server_private = [0x42u8; 32];
    let public = agreement::PrivateKey::from_private_key(&agreement::X25519, &server_private)
        .unwrap()
        .compute_public_key()
        .unwrap();
    let mut client = RealityClientConnection::new(RealityClientConfig {
        public_key: public.as_ref().try_into().unwrap(),
        short_id: SHORT_ID,
        server_name: "example.com".to_string(),
        cipher_suites: vec![],
    })
    .unwrap();
    let mut server = RealityServerConnection::new(RealityServerConfig {
        private_key: server_private,
        short_ids: vec![SHORT_ID],
        dest: NetLocation::new(Address::Hostname("example.com".to_string()), 443),
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: vec![],
    })
    .unwrap();

    let mut client_hello = Vec::new();
    client.write_tls(&mut client_hello).unwrap();
    server.validate_client_hello(&client_hello).unwrap();
    server.build_server_response(&[]).unwrap();

    server_to_client(&mut server, &mut client).unwrap();
    client_to_server(&mut client, &mut server).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    (client, server)
}

fn server_to_client(
    server: &mut RealityServerConnection,
    client: &mut RealityClientConnection,
) -> io::Result<()> {
    let mut wire = Vec::new();
    server.write_tls(&mut wire)?;
    client.read_tls(&mut io::Cursor::new(wire))?;
    client.process_new_packets().map(drop)
}

fn client_to_server(
    client: &mut RealityClientConnection,
    server: &mut RealityServerConnection,
) -> io::Result<()> {
    let mut wire = Vec::new();
    client.write_tls(&mut wire)?;
    server.read_tls(&mut io::Cursor::new(wire))?;
    server.process_new_packets().map(drop)
}

/// KeyUpdate(update_not_requested).
const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];

/// A NewSessionTicket: lifetime, age_add, nonce, ticket, no extensions.
const NEW_SESSION_TICKET: [u8; 19] = [
    4, 0, 0, 15, 0, 0, 0x1c, 0x20, 1, 2, 3, 4, 1, 9, 0, 2, 0xaa, 0xbb, 0,
];

#[test]
fn a_server_fails_a_key_update_instead_of_aborting() {
    let (mut client, mut server) = handshaken_pair();
    client.queue_post_handshake_message(&KEY_UPDATE);
    let err = client_to_server(&mut client, &mut server).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_client_fails_a_key_update_instead_of_aborting() {
    let (mut client, mut server) = handshaken_pair();
    server.queue_post_handshake_message(&KEY_UPDATE);
    let err = server_to_client(&mut server, &mut client).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_client_discards_a_session_ticket_and_keeps_reading() {
    let (mut client, mut server) = handshaken_pair();
    server.queue_post_handshake_message(&NEW_SESSION_TICKET);
    io::Write::write_all(&mut server.writer(), b"after").unwrap();
    server_to_client(&mut server, &mut client).unwrap();

    let mut got = [0u8; 5];
    io::Read::read_exact(&mut client.reader(), &mut got).unwrap();
    assert_eq!(&got, b"after");
}

#[test]
fn a_server_fails_a_session_ticket_from_a_client() {
    let (mut client, mut server) = handshaken_pair();
    client.queue_post_handshake_message(&NEW_SESSION_TICKET);
    let err = client_to_server(&mut client, &mut server).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}
