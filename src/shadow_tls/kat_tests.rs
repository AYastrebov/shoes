//! Against sing-shadowtls v3 (`tests/data/kat/shadowtls`): one connection
//! between its client and server, recorded both ways. Its HMACs never leave
//! the library, so they are checked where they cross the wire: the
//! ClientHello's session id, the server's tagged handshake records, and the
//! data frames in each direction.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::shadow_tls_hmac::{ShadowTlsHmac, tags_equal};
use super::shadow_tls_server_handler::{
    parse_validated_server_hello, read_client_hello, validate_shadowtls_client_hello,
};
use super::shadow_tls_stream::ShadowTlsStream;
use crate::async_stream::AsyncStream;
use crate::async_stream::testing::TestStream;
use crate::kat::{cases, hex, text, vectors};

fn initial_hmac(password: &str) -> ShadowTlsHmac {
    let key = aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        password.as_bytes(),
    );
    ShadowTlsHmac::new(&key)
}

fn records(vectors: &serde_json::Value, direction: &str) -> Vec<Vec<u8>> {
    cases(vectors, direction).iter().map(hex).collect()
}

/// The HMAC_ServerRandom chain both ends start from, and its "C" and "S"
/// branches for the client's and the server's data.
fn chains(vectors: &serde_json::Value) -> (ShadowTlsHmac, ShadowTlsHmac, ShadowTlsHmac) {
    let server_hello = &records(vectors, "server_to_client")[0];
    let server_random = parse_validated_server_hello(server_hello)
        .unwrap()
        .server_random;
    let mut server_random_chain = initial_hmac(text(&vectors["password"]));
    server_random_chain.update(&server_random);
    let mut client_data = server_random_chain.clone();
    client_data.update(b"C");
    let mut server_data = server_random_chain.clone();
    server_data.update(b"S");
    (server_random_chain, client_data, server_data)
}

/// A stream that yields `bytes` and then ends.
fn stream_of(bytes: Vec<u8>) -> Box<dyn AsyncStream> {
    let (near, mut far) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        far.write_all(&bytes).await.unwrap();
        far.shutdown().await.unwrap();
        let _ = far.read_to_end(&mut Vec::new()).await;
    });
    Box::new(TestStream(near))
}

#[tokio::test]
async fn the_reference_client_hello_carries_a_valid_session_id_tag() {
    let vectors = vectors("shadowtls");
    let client_hello = records(&vectors, "client_to_server").remove(0);
    let parsed = read_client_hello(&mut stream_of(client_hello))
        .await
        .unwrap();

    validate_shadowtls_client_hello(&parsed, &initial_hmac(text(&vectors["password"]))).unwrap();
    assert!(
        validate_shadowtls_client_hello(&parsed, &initial_hmac("another password")).is_err(),
        "the tag is keyed by the password"
    );
}

/// The server side of the stream reads the client's data frame. Which
/// record that is, the server finds as this test does: the first one whose
/// tag holds under HMAC_ServerRandomC.
#[tokio::test]
async fn the_reference_client_data_frame_reads_as_the_server_sees_it() {
    let vectors = vectors("shadowtls");
    let (_, client_data, server_data) = chains(&vectors);
    let after_hello = records(&vectors, "client_to_server").split_off(1);
    let first_data = after_hello
        .iter()
        .position(|record| {
            if record[0] != 0x17 || record.len() < 5 + 4 {
                return false;
            }
            let mut chain = client_data.clone();
            chain.update(&record[5 + 4..]);
            tags_equal(&record[5..5 + 4], &chain.digest())
        })
        .expect("no client record carries a data tag");

    let mut stream = ShadowTlsStream::new(
        stream_of(after_hello[first_data..].concat()),
        &[],
        client_data,
        server_data,
        None,
    )
    .unwrap();
    let mut message = Vec::new();
    stream.read_to_end(&mut message).await.unwrap();
    assert_eq!(message, hex(&vectors["client_message"]));
}

/// The client side reads the application-data records the server sent: the
/// decoy's, which the server tagged under HMAC_ServerRandom and the stream
/// must recognise and drop, then the server's data frame. The
/// ChangeCipherSpec between them belongs to the TLS handshake, which never
/// hands it to this stream.
#[tokio::test]
async fn the_reference_server_records_read_as_the_client_sees_them() {
    let vectors = vectors("shadowtls");
    let (server_random_chain, client_data, server_data) = chains(&vectors);
    let application_data: Vec<Vec<u8>> = records(&vectors, "server_to_client")
        .into_iter()
        .filter(|record| record[0] == 0x17)
        .collect();
    assert!(
        application_data.len() > 1,
        "the decoy's records and the data frame"
    );

    let mut stream = ShadowTlsStream::new(
        stream_of(application_data.concat()),
        &[],
        server_data,
        client_data,
        Some(server_random_chain),
    )
    .unwrap();
    let mut message = Vec::new();
    stream.read_to_end(&mut message).await.unwrap();
    assert_eq!(message, hex(&vectors["server_message"]));
}
