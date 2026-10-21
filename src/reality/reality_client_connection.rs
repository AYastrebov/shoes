#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

// REALITY client connection with rustls-compatible API

use std::io::{self, Read, Write};

use aws_lc_rs::kem;
use aws_lc_rs::{agreement, digest};
use rand::Rng;

use super::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, MAX_TLS_PLAINTEXT_LEN,
    PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE, TLS_RECORD_HEADER_SIZE,
    check_post_handshake_messages,
};
use super::reality_aead::{AeadKey, decrypt_handshake_message};
use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use super::reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
use super::reality_client_hello::{
    ClientKeyShares, EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD, GROUP_X25519,
    GROUP_X25519_MLKEM768, MLKEM768_CIPHERTEXT_LEN, client_hello_record,
    construct_chrome_client_hello,
};
use super::reality_client_verify::{
    extract_certificate_der, extract_certificate_verify_signature, extract_ed25519_public_key,
    verify_certificate_hmac, verify_certificate_verify_signature,
};
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{RecordDecryptor, RecordEncryptor};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::{DEFAULT_ALPN_PROTOCOLS, construct_finished};
use super::reality_util::{extract_server_cipher_suite, extract_server_key_share};
use crate::slide_buffer::SlideBuffer;
use crate::util::allocate_vec;

// Matches the maximum handshake size accepted by Xray's REALITY implementation.
const MAX_HANDSHAKE_PLAINTEXT: usize = 4 * MAX_TLS_PLAINTEXT_LEN;

/// The ServerHello random that marks a HelloRetryRequest (RFC 8446 4.1.3).
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A HelloRetryRequest means the server wants a group this client did not
/// send a share for; the client does not retry, so it says which.
fn reject_hello_retry_request(record: &[u8]) -> io::Result<()> {
    // Record header (5), handshake header (4), legacy version (2), random.
    const RANDOM_AT: usize = 5 + 4 + 2;
    if record.len() >= RANDOM_AT + 32
        && record[RANDOM_AT..RANDOM_AT + 32] == HELLO_RETRY_REQUEST_RANDOM
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server sent a HelloRetryRequest: it wants a key exchange group this client does \
             not offer",
        ));
    }
    Ok(())
}

/// The (EC)DHE input to the TLS 1.3 key schedule for the group the server
/// chose. For X25519MLKEM768 that is the ML-KEM shared secret followed by the
/// X25519 one (draft-ietf-tls-ecdhe-mlkem), 64 bytes where X25519 gives 32.
fn key_exchange_secret(
    group: u16,
    server_share: &[u8],
    x25519_private: &[u8; 32],
    mlkem_key: Option<&kem::DecapsulationKey<kem::AlgorithmId>>,
) -> io::Result<Vec<u8>> {
    let x25519 = |peer: &[u8]| -> io::Result<Vec<u8>> {
        let private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, x25519_private)
                .map_err(|_| io::Error::other("Failed to create private key"))?;
        agreement::agree(
            &private_key,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
            io::Error::other("ECDH failed"),
            |key_material| Ok(key_material.to_vec()),
        )
    };
    match group {
        GROUP_X25519 => x25519(server_share),
        GROUP_X25519_MLKEM768 => {
            let mlkem_key = mlkem_key.ok_or_else(|| {
                io::Error::other("server chose X25519MLKEM768, which was not offered")
            })?;
            if server_share.len() != MLKEM768_CIPHERTEXT_LEN + 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X25519MLKEM768 server share has the wrong length",
                ));
            }
            let (ciphertext, x25519_public) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
            let mlkem_secret = mlkem_key
                .decapsulate(kem::Ciphertext::from(ciphertext))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ML-KEM-768 decapsulation failed",
                    )
                })?;
            let mut secret = mlkem_secret.as_ref().to_vec();
            secret.extend_from_slice(&x25519(x25519_public)?);
            Ok(secret)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("server chose an unsupported key exchange group 0x{other:04x}"),
        )),
    }
}

/// CompressedCertificate (RFC 8879).
const HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE: u8 = 25;

/// EncryptedExtensions that negotiate ALPS would need a client
/// EncryptedExtensions in reply, which this client does not send.
fn reject_unimplemented_extensions(encrypted_extensions: &[u8]) -> io::Result<()> {
    let Some(list) = encrypted_extensions.get(2..) else {
        return Ok(());
    };
    let mut at = 0;
    while at + 4 <= list.len() {
        let ext_type = u16::from_be_bytes([list[at], list[at + 1]]);
        let ext_len = u16::from_be_bytes([list[at + 2], list[at + 3]]) as usize;
        if ext_type == EXT_APPLICATION_SETTINGS || ext_type == EXT_APPLICATION_SETTINGS_OLD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server negotiated application_settings (ALPS), which this client advertises \
                 but does not implement",
            ));
        }
        at += 4 + ext_len;
    }
    Ok(())
}

fn append_handshake_plaintext(accumulated: &mut Vec<u8>, plaintext: &[u8]) -> io::Result<usize> {
    let previous_len = accumulated.len();
    if previous_len.saturating_add(plaintext.len()) > MAX_HANDSHAKE_PLAINTEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY handshake exceeds maximum size",
        ));
    }
    accumulated.extend_from_slice(plaintext);
    Ok(previous_len)
}

/// The client version the REALITY client reports when its config sets none:
/// Xray-core's latest stable release.
///
/// Checked on 21 October 2026 against the releases of `XTLS/Xray-core`:
/// v26.3.27 is the latest release not marked as a pre-release. A server
/// compares this against its `minClientVer` and `maxClientVer`, and Xray
/// v26.7.28 (the version the Amnezia app installs) sets the minimum to
/// 26.3.27 when its config gives none (`infra/conf/transport_security.go`,
/// commit `af7eb68`), so an older version is sent to the decoy site.
const LATEST_STABLE_XRAY_CORE_VERSION: [u8; 3] = [26, 3, 27];

/// Configuration for REALITY client connections
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's X25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Short ID for authentication (8 bytes)
    pub short_id: [u8; 8],
    /// Server name for SNI
    pub server_name: String,
    /// Supported TLS 1.3 cipher suites (empty = use defaults)
    pub cipher_suites: Vec<CipherSuite>,
    /// The client version reported in the session ID
    /// (`None` = `LATEST_STABLE_XRAY_CORE_VERSION`)
    pub client_version: Option<[u8; 3]>,
}

/// Handshake state machine for REALITY client
enum HandshakeState {
    /// ClientHello sent, waiting for ServerHello
    AwaitingServerHello {
        client_hello_bytes: Vec<u8>, // Full ClientHello handshake message (raw bytes for transcript)
        client_private_key: [u8; 32],
        /// The ML-KEM-768 half of the X25519MLKEM768 share, for when the
        /// server picks the hybrid.
        mlkem_key: Option<Box<kem::DecapsulationKey<kem::AlgorithmId>>>,
        auth_key: [u8; 32], // REALITY authentication key for HMAC verification
    },
    /// ServerHello received, processing encrypted handshake messages
    ProcessingHandshake {
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: CipherSuite,
        handshake_transcript_bytes: Vec<u8>, // Accumulated transcript for hash computation
        auth_key: [u8; 32],                  // REALITY authentication key for HMAC verification
        // State for handling multiple encrypted handshake records (separate mode)
        handshake_seq: u64,             // Sequence number for decrypting records
        accumulated_plaintext: Vec<u8>, // Accumulated plaintext across records
        messages_found: u8,             // Number of handshake messages found so far
        certificate_verified: bool,     // Whether Certificate HMAC was verified
        ed25519_public_key: Option<[u8; 32]>, // Public key from Certificate for CV verification
        cert_verify_offset: Option<usize>, // Offset of CertificateVerify in accumulated plaintext
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// REALITY client-side connection implementing rustls-compatible API
pub struct RealityClientConnection {
    // Configuration
    config: RealityClientConfig,

    // Handshake state
    handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    // Keys are cached as AeadKey to avoid per-record key setup overhead
    app_read_key: Option<AeadKey>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<AeadKey>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: Option<CipherSuite>,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    tls_read_buffer: Box<[u8]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    plaintext_read_buf: SlideBuffer,  // Decrypted application data
    plaintext_write_buf: Vec<u8>,     // Application data to encrypt

    // Connection state flags (mirrors rustls patterns)
    received_close_notify: bool,        // Peer sent close_notify alert
    fatal_error: Option<io::ErrorKind>, // Fatal error occurred, connection unusable
}

impl RealityClientConnection {
    /// Create a new REALITY client connection and generate ClientHello
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        let mut conn = RealityClientConnection {
            config,
            handshake_state: HandshakeState::AwaitingServerHello {
                client_hello_bytes: Vec::new(),
                client_private_key: [0u8; 32],
                mlkem_key: None,
                auth_key: [0u8; 32],
            },
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: None,
            tls_read_buffer: allocate_vec(TLS_MAX_RECORD_SIZE).into_boxed_slice(),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::new(),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::new(),
            received_close_notify: false,
            fatal_error: None,
        };

        conn.generate_client_hello()?;

        Ok(conn)
    }

    /// Generate and buffer ClientHello
    fn generate_client_hello(&mut self) -> io::Result<()> {
        let mut rng = rand::rng();

        let mut our_private_bytes = [0u8; 32];
        rng.fill_bytes(&mut our_private_bytes);

        let our_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &our_private_bytes)
                .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        let mut client_random = [0u8; 32];
        rng.fill_bytes(&mut client_random);

        // Perform ECDH with server's public key to derive auth key
        let shared_secret = perform_ecdh(&our_private_bytes, &self.config.public_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Use slice directly from client_random to avoid copying
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Create session ID with REALITY metadata
        let timestamp = crate::util::unix_time_secs()?;

        let mut session_id_plaintext = [0u8; 16];
        // Client version [major, minor, patch], then a zero padding byte
        let client_version = self
            .config
            .client_version
            .unwrap_or(LATEST_STABLE_XRAY_CORE_VERSION);
        session_id_plaintext[0..3].copy_from_slice(&client_version);
        // Timestamp (4 bytes as uint32, in seconds)
        session_id_plaintext[4..8].copy_from_slice(&(timestamp as u32).to_be_bytes());
        // Short ID (8 bytes)
        session_id_plaintext[8..16].copy_from_slice(&self.config.short_id);

        // Create a 32-byte SessionId (16 bytes plaintext + 16 bytes zeros for padding)
        let mut session_id_for_hello = [0u8; 32];
        session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

        // Build ClientHello with plaintext SessionId first
        // Use configured cipher suites or defaults if none specified
        let cipher_suites = if self.config.cipher_suites.is_empty() {
            DEFAULT_CIPHER_SUITES.to_vec()
        } else {
            self.config.cipher_suites.clone()
        };
        let cipher_suite_ids: Vec<u16> = cipher_suites.iter().map(|cs| cs.id()).collect();

        // Chrome offers X25519MLKEM768 ahead of X25519, with one X25519 key
        // in both; a decoy that supports the hybrid picks it.
        let mlkem_key = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
            .map_err(|_| io::Error::other("Failed to generate an ML-KEM-768 key"))?;
        let mlkem_encapsulation_key = mlkem_key
            .encapsulation_key()
            .and_then(|key| key.key_bytes())
            .map_err(|_| io::Error::other("Failed to encode the ML-KEM-768 key"))?;
        let x25519_public: [u8; 32] = our_public_key_bytes
            .as_ref()
            .try_into()
            .map_err(|_| io::Error::other("X25519 public key is not 32 bytes"))?;
        let mut client_hello = construct_chrome_client_hello(
            &client_random,
            &session_id_for_hello,
            &ClientKeyShares {
                x25519_public: &x25519_public,
                mlkem768_encapsulation_key: mlkem_encapsulation_key.as_ref(),
            },
            &self.config.server_name,
            &cipher_suite_ids,
            DEFAULT_ALPN_PROTOCOLS,
        )?;

        // Now encrypt the SessionId using the ClientHello with zeroed SessionId as AAD
        // Use slice directly from client_random to avoid copying
        let nonce = &client_random[20..32];

        // Zero out the SessionId in ClientHello to create AAD (matches what server will use)
        // SessionId is at offset 39 in ClientHello handshake
        client_hello[39..71].fill(0);

        // The auth key and the plaintext (which carries the short_id) stay out
        // of the log: debug logging is runtime-switchable, and the short_id
        // identifies the deployment the way a password identifies an account.
        log::debug!(
            "REALITY CLIENT: Encrypting SessionId, aad_len={} (ClientHello with zero SessionId)",
            client_hello.len()
        );

        let encrypted_session_id =
            encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        log::debug!(
            "REALITY CLIENT: Encrypted SessionId={:02x?}",
            encrypted_session_id
        );

        // Restore the encrypted SessionId before writing or storing ClientHello.
        // REALITY transcripts use the wire ClientHello, not the zeroed AAD form.
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        let record = client_hello_record(&client_hello);
        self.ciphertext_write_buf.extend_from_slice(&record);

        // Store the wire ClientHello bytes for transcript hashing after ServerHello.
        // At this point client_hello contains the encrypted SessionId.
        self.handshake_state = HandshakeState::AwaitingServerHello {
            client_hello_bytes: client_hello, // Save the actual ClientHello bytes
            client_private_key: our_private_bytes,
            mlkem_key: Some(Box::new(mlkem_key)),
            auth_key, // Save auth_key for HMAC certificate verification
        };

        log::debug!(
            "REALITY: ClientHello generated and buffered ({} bytes)",
            record.len()
        );

        Ok(())
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
    /// Uses pre-allocated buffer to avoid allocation on every call.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        if self.ciphertext_read_buf.remaining_capacity() < TLS_MAX_RECORD_SIZE {
            self.ciphertext_read_buf.compact();
        }

        let n = rd.read(&mut self.tls_read_buffer[..])?;
        if n > 0 {
            self.ciphertext_read_buf
                .extend_from_slice(&self.tls_read_buffer[..n]);
        }
        Ok(n)
    }

    /// Process buffered packets and advance state machine
    ///
    /// Like rustls, this loops until no more progress can be made, ensuring
    /// that piggybacked application data is processed in the same call.
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        // RFC 8446: don't process data after close_notify
        if self.received_close_notify {
            return Ok(RealityIoState::new(self.plaintext_read_buf.len()));
        }

        let result = self.process_new_packets_inner();

        if let Err(ref e) = result {
            match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(e.kind());
                }
                _ => {}
            }
        }

        result
    }

    /// Inner implementation of process_new_packets
    fn process_new_packets_inner(&mut self) -> io::Result<RealityIoState> {
        loop {
            match &self.handshake_state {
                HandshakeState::AwaitingServerHello { .. } => {
                    if !self.process_server_hello()? {
                        break;
                    }
                }
                HandshakeState::ProcessingHandshake { .. } => {
                    if !self.process_encrypted_handshake()? {
                        break;
                    }
                }
                HandshakeState::Complete => {
                    self.process_application_data()?;
                    break;
                }
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Process ServerHello
    /// Returns true if a complete record was processed, false if more data needed
    #[inline]
    fn process_server_hello(&mut self) -> io::Result<bool> {
        let HandshakeState::AwaitingServerHello {
            client_hello_bytes,
            client_private_key,
            mlkem_key,
            auth_key,
        } = &self.handshake_state
        else {
            unreachable!()
        };

        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        // record_len is an unbounded peer-supplied u16; reject anything larger than the
        // fixed ciphertext buffer can hold (it could never complete and would overflow
        // the buffer on the next read) rather than crashing pre-authentication.
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if total_record_len > TLS_MAX_RECORD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record length exceeds maximum",
            ));
        }
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        // Clone fields before consuming buffer
        let client_hello_bytes = client_hello_bytes.clone();

        let record: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);
        let server_hello = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header (includes handshake header)

        log::debug!(
            "REALITY CLIENT: ServerHello for transcript: len={}, bytes={:02x?}",
            server_hello.len(),
            server_hello
        );

        reject_hello_retry_request(&record)?;
        let (server_group, server_share) = extract_server_key_share(&record)?;
        log::debug!("REALITY CLIENT: server chose key exchange group 0x{server_group:04x}");
        let cipher_suite_id = extract_server_cipher_suite(&record)?;
        let cipher_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Server selected unsupported cipher suite: 0x{:04x}",
                    cipher_suite_id
                ),
            )
        })?;
        log::debug!(
            "REALITY CLIENT: Server selected cipher suite 0x{:04x}",
            cipher_suite_id
        );

        // Compute transcript hash using negotiated cipher suite's algorithm
        let mut full_transcript = digest::Context::new(cipher_suite.digest_algorithm());
        log::debug!(
            "REALITY CLIENT: Transcript includes ClientHello ({} bytes), first bytes: {:02x?}",
            client_hello_bytes.len(),
            &client_hello_bytes[..client_hello_bytes.len().min(20)]
        );
        log::debug!(
            "REALITY CLIENT: Transcript includes ServerHello ({} bytes), first bytes: {:02x?}",
            server_hello.len(),
            &server_hello[..server_hello.len().min(20)]
        );
        full_transcript.update(&client_hello_bytes); // Use actual ClientHello bytes, not hash!
        full_transcript.update(server_hello); // ServerHello already includes handshake header
        let server_hello_hash = full_transcript.finish();
        let server_hello_hash_vec: Vec<u8> = server_hello_hash.as_ref().to_vec();

        let client_hello_hash_vec: Vec<u8> = {
            let mut ctx = digest::Context::new(cipher_suite.digest_algorithm());
            ctx.update(&client_hello_bytes);
            ctx.finish().as_ref().to_vec()
        };

        let tls_shared_secret = key_exchange_secret(
            server_group,
            &server_share,
            client_private_key,
            mlkem_key.as_deref(),
        )?;

        let hs_keys = derive_handshake_keys(
            cipher_suite,
            &tls_shared_secret,
            &client_hello_hash_vec,
            &server_hello_hash_vec,
        )?;

        log::debug!("REALITY: ServerHello processed, handshake keys derived");

        // Use actual bytes (not hashes) for transcript
        let mut transcript_bytes = Vec::new();
        transcript_bytes.extend_from_slice(&client_hello_bytes);
        transcript_bytes.extend_from_slice(server_hello);

        self.handshake_state = HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret.clone(),
            server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret.clone(),
            master_secret: hs_keys.master_secret.clone(),
            cipher_suite,
            handshake_transcript_bytes: transcript_bytes,
            auth_key: *auth_key, // Pass auth_key for certificate HMAC verification
            // Initialize state for handling multiple encrypted handshake records
            handshake_seq: 0,
            accumulated_plaintext: Vec::new(),
            messages_found: 0,
            certificate_verified: false,
            ed25519_public_key: None,
            cert_verify_offset: None,
        };

        Ok(true)
    }

    /// Process encrypted handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished)
    /// Handles both combined (1 record) and separate (multiple records) modes.
    /// Returns true if a complete record was processed, false if more data needed
    #[inline]
    fn process_encrypted_handshake(&mut self) -> io::Result<bool> {
        let HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_transcript_bytes,
            auth_key,
            handshake_seq,
            accumulated_plaintext,
            messages_found,
            certificate_verified,
            ed25519_public_key,
            cert_verify_offset,
        } = &self.handshake_state
        else {
            unreachable!()
        };

        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(server_handshake_traffic_secret, *cipher_suite)?;

        if *handshake_seq == 0 {
            log::debug!(
                "REALITY CLIENT: Server HS key={:02x?}, iv={:02x?}",
                &server_hs_key[..16],
                server_hs_iv
            );
        }

        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_type = self.ciphertext_read_buf[0];
        let tls_version = self
            .ciphertext_read_buf
            .get_u16_be(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?;
        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        log::debug!(
            "REALITY CLIENT: TLS record header: type=0x{:02x}, version=0x{:04x}, len={}",
            record_type,
            tls_version,
            record_len
        );

        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if total_record_len > TLS_MAX_RECORD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record length exceeds maximum",
            ));
        }
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        // Skip ChangeCipherSpec (dummy in TLS 1.3)
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            log::debug!(
                "REALITY CLIENT: Skipping ChangeCipherSpec record ({} bytes)",
                record_len
            );
            self.ciphertext_read_buf.consume(total_record_len);
            return self.process_encrypted_handshake();
        }

        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected Application Data record, got 0x{:02x}",
                    record_type
                ),
            ));
        }

        // NOW we're committed to processing - clone/copy fields we need to modify
        let client_hs_secret = client_handshake_traffic_secret.clone();
        let server_hs_secret = server_handshake_traffic_secret.clone();
        let master_secret = master_secret.clone();
        let transcript_bytes = handshake_transcript_bytes.clone();
        let mut accumulated_plaintext = accumulated_plaintext.clone();
        let cipher_suite = *cipher_suite;
        let auth_key = *auth_key;
        let mut handshake_seq = *handshake_seq;
        let mut messages_found = *messages_found;
        let mut certificate_verified = *certificate_verified;
        let mut ed25519_public_key = *ed25519_public_key;
        let mut cert_verify_offset = *cert_verify_offset;

        // Copy and extract the encrypted handshake record
        let ciphertext: Vec<u8> =
            self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);

        log::debug!(
            "REALITY CLIENT: Decrypting handshake record #{} - record_len={}",
            handshake_seq,
            record_len
        );

        // Decrypt using current sequence number
        let plaintext = decrypt_handshake_message(
            cipher_suite,
            &server_hs_key,
            &server_hs_iv,
            handshake_seq,
            &ciphertext,
            record_len as u16,
        )?;

        log::debug!(
            "REALITY CLIENT: Decrypted record #{} ({} bytes plaintext)",
            handshake_seq,
            plaintext.len()
        );

        handshake_seq += 1;

        // Track where new plaintext starts in accumulated buffer
        let prev_accumulated_len =
            append_handshake_plaintext(&mut accumulated_plaintext, &plaintext)?;

        // Parse newly added messages from the plaintext we just added
        let mut offset = prev_accumulated_len;
        while offset < accumulated_plaintext.len() && messages_found < 4 {
            // Each handshake message has: type (1 byte) + length (3 bytes) + data
            if offset + 4 > accumulated_plaintext.len() {
                break; // Incomplete message header, need more data
            }

            let msg_type = accumulated_plaintext[offset];
            let msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[offset + 1],
                accumulated_plaintext[offset + 2],
                accumulated_plaintext[offset + 3],
            ]) as usize;

            if offset + 4 + msg_len > accumulated_plaintext.len() {
                break; // Incomplete message body, need more data
            }

            let msg_name = match msg_type {
                HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
                HANDSHAKE_TYPE_CERTIFICATE => "Certificate",
                HANDSHAKE_TYPE_CERTIFICATE_VERIFY => "CertificateVerify",
                HANDSHAKE_TYPE_FINISHED => "Finished",
                _ => "Unknown",
            };

            log::debug!(
                "REALITY CLIENT: Found {} message (type={}, len={})",
                msg_name,
                msg_type,
                msg_len
            );

            // Advertised for the shape, implemented by neither end of an
            // authenticated Reality handshake; refuse them by name rather
            // than misparse what follows.
            if msg_type == HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS {
                reject_unimplemented_extensions(
                    &accumulated_plaintext[offset + 4..offset + 4 + msg_len],
                )?;
            }
            if msg_type == HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "server sent a compressed certificate, which this client advertises but does \
                     not implement",
                ));
            }

            // Verify HMAC signature when we encounter the Certificate message
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE {
                let cert_der =
                    extract_certificate_der(&accumulated_plaintext[offset..offset + 4 + msg_len])?;
                verify_certificate_hmac(cert_der, &auth_key)?;
                ed25519_public_key = Some(extract_ed25519_public_key(cert_der)?);
                certificate_verified = true;
            }

            // Record CertificateVerify offset for later verification
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                cert_verify_offset = Some(offset);
            }

            messages_found += 1;
            offset += 4 + msg_len;
        }

        if messages_found < 4 {
            log::debug!(
                "REALITY CLIENT: Received {} of 4 handshake messages, waiting for more records",
                messages_found
            );
            self.handshake_state = HandshakeState::ProcessingHandshake {
                client_handshake_traffic_secret: client_hs_secret,
                server_handshake_traffic_secret: server_hs_secret,
                master_secret,
                cipher_suite,
                handshake_transcript_bytes: transcript_bytes,
                auth_key,
                handshake_seq,
                accumulated_plaintext,
                messages_found,
                certificate_verified,
                ed25519_public_key,
                cert_verify_offset,
            };
            return Ok(true); // Processed a record, but need more
        }

        log::debug!(
            "REALITY CLIENT: All 4 handshake messages received ({} bytes total)",
            accumulated_plaintext.len()
        );

        // Ensure the Certificate message was present and HMAC verified
        if !certificate_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: Certificate message not received or not verified",
            ));
        }

        // Verify CertificateVerify signature
        let mut cert_verify_verified = false;
        if let (Some(public_key), Some(cv_offset)) = (ed25519_public_key, cert_verify_offset) {
            // Transcript up to (not including) CertificateVerify
            let mut cv_transcript = digest::Context::new(cipher_suite.digest_algorithm());
            cv_transcript.update(&transcript_bytes);
            cv_transcript.update(&accumulated_plaintext[..cv_offset]);
            let cv_transcript_hash = cv_transcript.finish();

            let cv_msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[cv_offset + 1],
                accumulated_plaintext[cv_offset + 2],
                accumulated_plaintext[cv_offset + 3],
            ]) as usize;
            let cv_message = &accumulated_plaintext[cv_offset..cv_offset + 4 + cv_msg_len];
            let signature = extract_certificate_verify_signature(cv_message)?;

            verify_certificate_verify_signature(
                &public_key,
                &signature,
                cv_transcript_hash.as_ref(),
            )?;
            cert_verify_verified = true;
        }

        if !cert_verify_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: CertificateVerify not verified",
            ));
        }

        let mut handshake_transcript = digest::Context::new(cipher_suite.digest_algorithm());
        handshake_transcript.update(&transcript_bytes);
        handshake_transcript.update(&accumulated_plaintext);

        let handshake_hash = handshake_transcript.finish();
        let handshake_hash_vec: Vec<u8> = handshake_hash.as_ref().to_vec();

        log::debug!(
            "REALITY CLIENT: Handshake hash for client Finished: {:02x?}",
            handshake_hash_vec
        );
        log::debug!(
            "REALITY CLIENT: Transcript bytes len={}, accumulated_plaintext len={}",
            transcript_bytes.len(),
            accumulated_plaintext.len()
        );

        let client_verify_data =
            compute_finished_verify_data(cipher_suite, &client_hs_secret, &handshake_hash_vec)?;
        log::debug!(
            "REALITY CLIENT: Client verify data: {:02x?}",
            client_verify_data
        );
        let client_finished = construct_finished(&client_verify_data)?;

        let (client_hs_key, client_hs_iv) = derive_traffic_keys(&client_hs_secret, cipher_suite)?;

        let mut client_hs_seq = 0u64;
        let buf_len_before = self.ciphertext_write_buf.len();
        let hs_aead_key = AeadKey::new(cipher_suite, &client_hs_key)?;
        {
            let mut encryptor =
                RecordEncryptor::new(&hs_aead_key, &client_hs_iv, &mut client_hs_seq);
            encryptor.encrypt_handshake(&client_finished, &mut self.ciphertext_write_buf)?;
        }

        log::debug!(
            "REALITY CLIENT: Client Finished message generated and buffered ({} bytes)",
            self.ciphertext_write_buf.len() - buf_len_before
        );

        let (client_app_secret, server_app_secret) =
            derive_application_secrets(cipher_suite, &master_secret, &handshake_hash_vec)?;

        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        // Cache AeadKey objects to avoid per-record key setup
        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;

        self.app_read_key = Some(server_app_key);
        self.app_read_iv = Some(server_app_iv);
        self.app_write_key = Some(client_app_key);
        self.app_write_iv = Some(client_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = Some(cipher_suite);
        self.handshake_state = HandshakeState::Complete;
        log::debug!("REALITY CLIENT: Handshake complete, application keys derived");

        Ok(true)
    }

    /// Decrypt application data using TLS 1.3 keys
    /// Processes all complete TLS records in the buffer
    #[inline]
    fn process_application_data(&mut self) -> io::Result<()> {
        let (app_read_key, app_read_iv) = match (&self.app_read_key, &self.app_read_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => unreachable!(), // Wrong state
        };

        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            let record_len = self
                .ciphertext_read_buf
                .get_u16_be(3)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
                as usize;

            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if total_record_len > TLS_MAX_RECORD_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record length exceeds maximum",
                ));
            }
            if self.ciphertext_read_buf.len() < total_record_len {
                break;
            }

            // Decrypt in-place: get mutable slice of ciphertext, decrypt, copy plaintext out
            let ciphertext_slice = self
                .ciphertext_read_buf
                .slice_mut(TLS_RECORD_HEADER_SIZE..total_record_len);
            let mut decryptor = RecordDecryptor::new(app_read_key, app_read_iv, &mut self.read_seq);
            let (content_type, plaintext) =
                decryptor.decrypt_record_in_place(ciphertext_slice, record_len as u16)?;

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    // Compact plaintext buffer if needed before extending
                    self.plaintext_read_buf.maybe_compact(4096);
                    self.plaintext_read_buf.extend_from_slice(plaintext);
                }
                CONTENT_TYPE_ALERT => {
                    // Parse alert: level (1 byte) + description (1 byte)
                    if plaintext.len() >= 2 {
                        let alert_level = plaintext[0];
                        let alert_desc = plaintext[1];

                        if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                            log::debug!("REALITY CLIENT: Received close_notify alert");
                            self.received_close_notify = true;
                            // Per RFC 8446: "Any data received after a closure alert
                            // has been received MUST be ignored."
                            return Ok(());
                        } else if alert_level != ALERT_LEVEL_WARNING {
                            // Fatal alert - connection must be terminated
                            log::warn!(
                                "REALITY CLIENT: Received fatal alert: level={}, desc={}",
                                alert_level,
                                alert_desc
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!("received fatal alert: {}", alert_desc),
                            ));
                        } else {
                            log::debug!(
                                "REALITY CLIENT: Received warning alert: desc={}",
                                alert_desc
                            );
                        }
                    }
                }
                CONTENT_TYPE_HANDSHAKE => {
                    check_post_handshake_messages(plaintext, true)?;
                    log::debug!("REALITY CLIENT: Discarded post-handshake NewSessionTicket");
                }
                // strip_content_type_slice admits only the three types above
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected content type 0x{:02x}", content_type),
                    ));
                }
            }

            // Consume the processed record from the buffer (after plaintext borrow ends)
            self.ciphertext_read_buf.consume(total_record_len);
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        // SlideBuffer handles compaction internally via maybe_compact()
        // Compact before returning reader if we've consumed significant data
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf, self.received_close_notify)
    }

    /// Get a writer for buffering plaintext to be encrypted
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(
            &mut self.plaintext_write_buf,
            self.ciphertext_write_buf.len(),
        )
    }

    /// Write buffered TLS messages to the provided writer
    ///
    /// Large plaintext is automatically fragmented into multiple TLS records
    /// to comply with the TLS 1.3 record size limit.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        // If handshake not complete, just write buffered handshake data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        // Encrypt any pending plaintext (with automatic fragmentation for large data)
        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Application keys not available",
                    ));
                }
            };

            let mut encryptor =
                RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
            encryptor.encrypt_app_data(
                &mut self.plaintext_write_buf,
                &mut self.ciphertext_write_buf,
            )?;
        }

        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    /// Check if handshake is still in progress
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.handshake_state, HandshakeState::Complete)
    }

    /// Check if the connection wants to read more TLS data
    ///
    /// Returns true if we need more data to make progress (handshake or decryption).
    /// This mirrors rustls::Connection::wants_read().
    pub fn wants_read(&self) -> bool {
        // Don't read more after receiving close_notify (RFC 8446)
        if self.received_close_notify {
            return false;
        }

        // Don't read more if we're in a fatal error state
        if self.fatal_error.is_some() {
            return false;
        }

        // During handshake, we always want to read
        if self.is_handshaking() {
            return true;
        }

        // After handshake, we want to read if:
        // 1. Plaintext buffer is empty (need more application data), OR
        // 2. Ciphertext buffer has incomplete records that need more data
        //
        // Note: If plaintext buffer has data, the caller should consume it first.
        // If ciphertext buffer has complete records, process_new_packets should be called.
        self.plaintext_read_buf.is_empty()
    }

    /// Seal `msg` as one post-handshake handshake record, as a peer that sends KeyUpdate
    /// or NewSessionTicket would.
    #[cfg(test)]
    pub(super) fn queue_post_handshake_message(&mut self, msg: &[u8]) {
        let (key, iv) = (
            self.app_write_key.as_ref().unwrap(),
            self.app_write_iv.as_ref().unwrap(),
        );
        RecordEncryptor::new(key, iv, &mut self.write_seq)
            .encrypt_handshake(msg, &mut self.ciphertext_write_buf)
            .unwrap();
    }

    /// Queue a close notification alert
    pub fn send_close_notify(&mut self) {
        // In TLS 1.3, alerts must be encrypted like application data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            log::debug!("REALITY CLIENT: Cannot send close_notify - handshake not complete");
            return;
        }

        // Get application keys
        let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                log::debug!(
                    "REALITY CLIENT: Cannot send close_notify - application keys not available"
                );
                return;
            }
        };

        // Encrypt close_notify alert using RecordEncryptor
        let mut encryptor = RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
        match encryptor.encrypt_close_notify(&mut self.ciphertext_write_buf) {
            Ok(()) => {
                log::debug!("REALITY CLIENT: Encrypted close_notify alert queued");
            }
            Err(e) => {
                log::error!("REALITY CLIENT: Failed to encrypt close_notify: {}", e);
            }
        }
    }
}

#[inline]
pub fn feed_reality_client_connection(
    client_connection: &mut RealityClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = client_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed TLS connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_plaintext_is_bounded() {
        let mut accumulated = vec![0; MAX_HANDSHAKE_PLAINTEXT];

        let error = append_handshake_plaintext(&mut accumulated, &[0]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(accumulated.len(), MAX_HANDSHAKE_PLAINTEXT);
    }

    const SERVER_PRIVATE: [u8; 32] = [0x42u8; 32];

    fn client(client_version: Option<[u8; 3]>) -> RealityClientConnection {
        let server_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &SERVER_PRIVATE).unwrap();
        let server_public_key = server_private_key.compute_public_key().unwrap();
        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(server_public_key.as_ref());

        RealityClientConnection::new(RealityClientConfig {
            public_key: server_public,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            server_name: "example.com".to_string(),
            cipher_suites: vec![],
            client_version,
        })
        .unwrap()
    }

    /// The session ID the client sealed into its ClientHello, opened the way
    /// the server opens it.
    fn sealed_session_id(client_version: Option<[u8; 3]>) -> [u8; 16] {
        use super::super::common::TLS_RECORD_HEADER_SIZE;
        use super::super::reality_auth::decrypt_session_id;
        use super::super::reality_util::{
            extract_client_public_key, extract_client_random, extract_session_id_slice,
        };

        let mut wire = Vec::new();
        client(client_version).write_tls(&mut wire).unwrap();

        let random = extract_client_random(&wire).unwrap();
        let sealed: [u8; 32] = extract_session_id_slice(&wire).unwrap().try_into().unwrap();
        let shared =
            perform_ecdh(&SERVER_PRIVATE, &extract_client_public_key(&wire).unwrap()).unwrap();
        let auth_key = derive_auth_key(&shared, &random[0..20], b"REALITY").unwrap();
        let mut aad = wire[TLS_RECORD_HEADER_SIZE..].to_vec();
        aad[39..39 + 32].fill(0);
        decrypt_session_id(&sealed, &auth_key, &random[20..32], &aad).unwrap()
    }

    #[test]
    fn the_session_id_carries_the_configured_version() {
        let plaintext = sealed_session_id(Some([26, 9, 8]));
        assert_eq!(plaintext[0..3], [26, 9, 8]);
        assert_eq!(plaintext[3], 0, "the byte after the version is padding");
    }

    /// Xray-core's latest stable release at the time of writing, 26.3.27.
    #[test]
    fn the_session_id_carries_the_latest_stable_xray_version_by_default() {
        assert_eq!(sealed_session_id(None)[0..3], [26, 3, 27]);
    }

    #[test]
    fn client_hello_transcript_bytes_use_encrypted_session_id() {
        let mut conn = client(None);
        let stored_client_hello = match &conn.handshake_state {
            HandshakeState::AwaitingServerHello {
                client_hello_bytes, ..
            } => client_hello_bytes.clone(),
            _ => panic!("new client must be awaiting ServerHello"),
        };

        let mut wire = Vec::new();
        conn.write_tls(&mut wire).unwrap();

        assert_eq!(&wire[5..], stored_client_hello.as_slice());
        assert_ne!(
            &stored_client_hello[39..71],
            &[0u8; 32],
            "transcript ClientHello must retain encrypted wire SessionId"
        );
    }
}

#[cfg(test)]
mod key_exchange_tests {
    use super::*;

    fn x25519_pair() -> ([u8; 32], Vec<u8>) {
        let mut private = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut private);
        let public = agreement::PrivateKey::from_private_key(&agreement::X25519, &private)
            .unwrap()
            .compute_public_key()
            .unwrap()
            .as_ref()
            .to_vec();
        (private, public)
    }

    /// The hybrid secret is the ML-KEM shared secret then the X25519 one, as
    /// a server that encapsulated to the client's key computes it.
    #[test]
    fn the_hybrid_secret_is_mlkem_then_x25519() {
        let (client_private, client_public) = x25519_pair();
        let (server_private, server_public) = x25519_pair();
        let mlkem_key = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
        let encapsulation_key = mlkem_key.encapsulation_key().unwrap().key_bytes().unwrap();

        // The server's side.
        let (ciphertext, server_mlkem_secret) =
            kem::EncapsulationKey::new(&kem::ML_KEM_768, encapsulation_key.as_ref())
                .unwrap()
                .encapsulate()
                .unwrap();
        let server_x25519_secret =
            key_exchange_secret(GROUP_X25519, &client_public, &server_private, None).unwrap();
        let mut share = ciphertext.as_ref().to_vec();
        share.extend_from_slice(&server_public);

        let secret = key_exchange_secret(
            GROUP_X25519_MLKEM768,
            &share,
            &client_private,
            Some(&mlkem_key),
        )
        .unwrap();
        assert_eq!(secret.len(), 64);
        assert_eq!(&secret[..32], server_mlkem_secret.as_ref());
        assert_eq!(&secret[32..], &server_x25519_secret[..]);
    }

    #[test]
    fn a_truncated_hybrid_share_fails() {
        let (client_private, _) = x25519_pair();
        let mlkem_key = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
        let err = key_exchange_secret(
            GROUP_X25519_MLKEM768,
            &[0u8; 1000],
            &client_private,
            Some(&mlkem_key),
        )
        .unwrap_err();
        assert!(err.to_string().contains("wrong length"), "{err}");
    }

    #[test]
    fn a_hello_retry_request_is_refused_by_name() {
        let mut record = vec![
            0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
        ];
        record.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        let err = reject_hello_retry_request(&record).unwrap_err();
        assert!(err.to_string().contains("HelloRetryRequest"), "{err}");
        record[11] ^= 1;
        assert!(reject_hello_retry_request(&record).is_ok());
    }

    #[test]
    fn alps_in_encrypted_extensions_is_refused_by_name() {
        // Extensions length, then application_settings with an empty body.
        let ee = [0x00, 0x04, 0x44, 0xcd, 0x00, 0x00];
        let err = reject_unimplemented_extensions(&ee).unwrap_err();
        assert!(err.to_string().contains("ALPS"), "{err}");
        assert!(reject_unimplemented_extensions(&[0x00, 0x04, 0x00, 0x10, 0x00, 0x00]).is_ok());
    }
}
