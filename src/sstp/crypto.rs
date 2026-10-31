//! MS-CHAPv2 (RFC 2759 §8), the MPPE master keys it yields (RFC 3079 §3),
//! and SSTP's crypto binding built on them ([MS-SSTP] §3.2.5.2).
//!
//! Every function here is a transcription of the routine its document names,
//! checked against the vectors printed in those documents and against
//! sstp-client's test data (`tests/data/kat/sstp/`). MD4 and single DES are
//! what MS-CHAPv2 is; nothing here chooses them.

use aws_lc_rs::{digest, hmac};
use des::Des;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use md4::{Digest, Md4};
use zeroize::Zeroizing;

/// RFC 2759 §8.7, "Magic server to client signing constant".
const AUTH_MAGIC_1: &[u8; 39] = b"Magic server to client signing constant";
/// RFC 2759 §8.7, "Pad to make it do more than one iteration".
const AUTH_MAGIC_2: &[u8; 41] = b"Pad to make it do more than one iteration";

/// RFC 3079 §3.4, Magic1.
const MPPE_MAGIC_1: &[u8; 27] = b"This is the MPPE Master Key";
/// RFC 3079 §3.4, Magic2: the client's send key, the server's receive key.
const MPPE_MAGIC_2: &[u8; 84] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
/// RFC 3079 §3.4, Magic3: the client's receive key, the server's send key.
const MPPE_MAGIC_3: &[u8; 84] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";
/// RFC 3079 §3.4, SHSpad1 and SHSpad2.
const SHS_PAD_1: [u8; 40] = [0x00; 40];
const SHS_PAD_2: [u8; 40] = [0xf2; 40];

/// [MS-SSTP] §3.2.5.2.2, the Compound MAC Key seed.
const CMK_SEED: &[u8; 29] = b"SSTP inner method derived CMK";

/// The hash an SSTP server offered and the client chose for crypto binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingHash {
    Sha1,
    Sha256,
}

impl BindingHash {
    /// The `Hash Protocol` byte of the Crypto Binding attribute (§2.2.7).
    pub fn protocol_byte(self) -> u8 {
        match self {
            BindingHash::Sha1 => 0x01,
            BindingHash::Sha256 => 0x02,
        }
    }

    /// Output length of the hash, and so of the Cert Hash and Compound MAC.
    pub fn len(self) -> usize {
        match self {
            BindingHash::Sha1 => 20,
            BindingHash::Sha256 => 32,
        }
    }

    fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            BindingHash::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            BindingHash::Sha256 => hmac::HMAC_SHA256,
        }
    }

    fn digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            BindingHash::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            BindingHash::Sha256 => &digest::SHA256,
        }
    }

    /// The Cert Hash: this hash of the server's leaf certificate.
    pub fn cert_hash(self, certificate_der: &[u8]) -> Vec<u8> {
        digest::digest(self.digest_algorithm(), certificate_der)
            .as_ref()
            .to_vec()
    }
}

/// NtPasswordHash (RFC 2759 §8.3): MD4 of the password as UTF-16LE, with no
/// terminating zero.
pub fn nt_password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let unicode: Zeroizing<Vec<u8>> =
        Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    md4_16(&unicode)
}

/// HashNtPasswordHash (§8.4): MD4 of the hash.
fn hash_nt_password_hash(password_hash: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    md4_16(password_hash)
}

fn md4_16(data: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&Md4::digest(data));
    out
}

/// The account name the challenge hash takes: RFC 2759 §4 and §8.2 use the
/// user name "excluding any prepended domain name", so `BIGCO\johndoe` hashes
/// as `johndoe`. The Response packet's Name field still carries the whole
/// name. SoftEther strips it the same way (`Proto_PPP.c:4401`); accel-ppp
/// does not, which only matters for a name that has a domain.
pub fn account_name(username: &str) -> &str {
    username
        .rsplit_once('\\')
        .map_or(username, |(_, name)| name)
}

/// ChallengeHash (§8.2): the first 8 octets of
/// SHA-1(PeerChallenge | AuthenticatorChallenge | account name).
fn challenge_hash(
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &str,
) -> [u8; 8] {
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(peer_challenge);
    context.update(authenticator_challenge);
    context.update(account_name(username).as_bytes());
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&context.finish().as_ref()[..8]);
    challenge
}

/// The 56-bit key in 7 octets spread across 8, each with odd parity in its
/// low bit (RFC 2759 §8.6 and the example in §9.3). DES ignores the parity
/// bits, but setting them makes the key the one the RFC prints.
fn des_key(seven: &[u8]) -> [u8; 8] {
    let bits = seven.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut key = [0u8; 8];
    for (i, byte) in key.iter_mut().enumerate() {
        let septet = ((bits >> (49 - 7 * i)) & 0x7f) as u8;
        let high = septet << 1;
        *byte = high | u8::from(high.count_ones().is_multiple_of(2));
    }
    key
}

/// ChallengeResponse (§8.5): the 8-octet challenge DES-encrypted under each
/// third of the password hash zero-padded to 21 octets.
fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut padded = Zeroizing::new([0u8; 21]);
    padded[..16].copy_from_slice(password_hash);
    let mut response = [0u8; 24];
    for (i, out) in response.chunks_exact_mut(8).enumerate() {
        let key = Zeroizing::new(des_key(&padded[i * 7..i * 7 + 7]));
        let cipher = Des::new(&(*key).into());
        let mut block = (*challenge).into();
        cipher.encrypt_block(&mut block);
        out.copy_from_slice(&block);
    }
    response
}

/// GenerateNTResponse (§8.1): the 24 octets a Response packet carries.
pub fn generate_nt_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &str,
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    challenge_response(&challenge, &nt_password_hash(password))
}

/// GenerateAuthenticatorResponse (§8.7): the 20-octet digest a Success
/// packet's `S=` field carries as 40 hex digits.
pub fn authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &str,
) -> [u8; 20] {
    let password_hash_hash = hash_nt_password_hash(&nt_password_hash(password));

    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(&*password_hash_hash);
    context.update(nt_response);
    context.update(AUTH_MAGIC_1);
    let first = context.finish();

    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(first.as_ref());
    context.update(&challenge);
    context.update(AUTH_MAGIC_2);
    let mut out = [0u8; 20];
    out.copy_from_slice(context.finish().as_ref());
    out
}

/// GetMasterKey (RFC 3079 §3.4).
fn master_key(password_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> Zeroizing<[u8; 16]> {
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(password_hash_hash);
    context.update(nt_response);
    context.update(MPPE_MAGIC_1);
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&context.finish().as_ref()[..16]);
    out
}

/// GetAsymmetricStartKey (RFC 3079 §3.4) for 128-bit keys.
fn asymmetric_start_key(master_key: &[u8; 16], send: bool, server: bool) -> Zeroizing<[u8; 16]> {
    let magic = if send == server {
        MPPE_MAGIC_3
    } else {
        MPPE_MAGIC_2
    };
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(master_key);
    context.update(&SHS_PAD_1);
    context.update(magic);
    context.update(&SHS_PAD_2);
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&context.finish().as_ref()[..16]);
    out
}

/// One side's MPPE master keys after MS-CHAPv2.
pub struct MppeKeys {
    pub send: Zeroizing<[u8; 16]>,
    pub receive: Zeroizing<[u8; 16]>,
}

/// The master send and receive keys (RFC 3079 §3.3), as the client
/// (`server == false`) or the server sees them.
pub fn mppe_keys(password: &str, nt_response: &[u8; 24], server: bool) -> MppeKeys {
    let password_hash_hash = hash_nt_password_hash(&nt_password_hash(password));
    let master = master_key(&password_hash_hash, nt_response);
    MppeKeys {
        send: asymmetric_start_key(&master, true, server),
        receive: asymmetric_start_key(&master, false, server),
    }
}

/// The 32-octet Higher-Layer Authentication Key (§3.2.5.2.2).
pub type Hlak = Zeroizing<[u8; 32]>;

impl MppeKeys {
    /// `MasterSendKey | MasterReceiveKey`, which is the client's HLAK from
    /// its own keys and the server's HLAK from the server's, since each
    /// side's send key is the other's receive key.
    pub fn hlak(&self) -> Hlak {
        let mut hlak = Zeroizing::new([0u8; 32]);
        hlak[..16].copy_from_slice(&*self.send);
        hlak[16..].copy_from_slice(&*self.receive);
        hlak
    }
}

/// The HLAK of a method that produces no keys, PAP among them: 32 zeros.
pub fn zero_hlak() -> Hlak {
    Zeroizing::new([0u8; 32])
}

/// The Compound MAC Key (§3.2.5.2.2 and .4): the first block of PRF+, which
/// is all of it, since the key is one hash long. LEN is a 16-bit integer
/// encoded little-endian, as sstp-client (`sstp-cmac.c:177-190`) and
/// Open-SSTP-Client (`SstpClietnt.kt:42-56`) both write it.
fn compound_mac_key(hlak: &[u8; 32], hash: BindingHash) -> hmac::Tag {
    let key = hmac::Key::new(hash.hmac_algorithm(), hlak);
    let mut context = hmac::Context::with_key(&key);
    context.update(CMK_SEED);
    context.update(&(hash.len() as u16).to_le_bytes());
    context.update(&[0x01]);
    context.sign()
}

/// The Compound MAC over a Call Connected message whose MAC and padding
/// fields are zero (§3.2.5.2.1 and .3).
pub fn compound_mac(hlak: &[u8; 32], hash: BindingHash, call_connected: &[u8]) -> Vec<u8> {
    let cmk = compound_mac_key(hlak, hash);
    let key = hmac::Key::new(hash.hmac_algorithm(), cmk.as_ref());
    hmac::sign(&key, call_connected).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    /// The constants are the RFCs' byte arrays, transcribed as text; their
    /// lengths are the ones the RFCs declare, so a dropped character shows.
    #[test]
    fn the_magic_constants_have_the_lengths_the_rfcs_declare() {
        assert_eq!(AUTH_MAGIC_1.len(), 39);
        assert_eq!(AUTH_MAGIC_2.len(), 41);
        assert_eq!(MPPE_MAGIC_1.len(), 27);
        assert_eq!(MPPE_MAGIC_2.len(), 84);
        assert_eq!(MPPE_MAGIC_3.len(), 84);
        assert_eq!(CMK_SEED.len(), 29);
    }

    /// RFC 2759 §9.3: the parity-corrected DES keys for "MyPw".
    #[test]
    fn des_keys_are_spread_with_odd_parity() {
        assert_eq!(
            des_key(&hex("FC 15 6A F7 ED CD 6C")),
            arr::<8>("FD 0B 5B 5E 7F 6E 34 D9")
        );
        assert_eq!(
            des_key(&hex("0E DD E3 33 7D 42 7F")),
            arr::<8>("0E 6E 79 67 37 EA 08 FE")
        );
    }

    /// RFC 2759 §9.2, every intermediate value.
    #[test]
    fn ms_chap_v2_matches_rfc_2759() {
        let authenticator_challenge = arr::<16>("5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28");
        let peer_challenge = arr::<16>("21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E");

        assert_eq!(
            challenge_hash(&peer_challenge, &authenticator_challenge, "User"),
            arr::<8>("D0 2E 43 86 BC E9 12 26")
        );
        assert_eq!(
            *nt_password_hash("clientPass"),
            arr::<16>("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE")
        );
        let nt_response = generate_nt_response(
            &authenticator_challenge,
            &peer_challenge,
            "User",
            "clientPass",
        );
        assert_eq!(
            nt_response,
            arr::<24>("82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF")
        );
        assert_eq!(
            authenticator_response(
                "clientPass",
                &nt_response,
                &peer_challenge,
                &authenticator_challenge,
                "User"
            ),
            arr::<20>("407A5589115FD0D6209F510FE9C04566932CDA56")
        );
    }

    /// RFC 2759 §4 and §8.2: a domain before the name does not enter the
    /// challenge hash, so `BIGCO\User` answers exactly as `User` does.
    #[test]
    fn the_domain_is_left_out_of_the_challenge_hash() {
        let a = [1u8; 16];
        let p = [2u8; 16];
        assert_eq!(
            challenge_hash(&p, &a, "BIGCO\\User"),
            challenge_hash(&p, &a, "User")
        );
        assert_eq!(account_name("BIGCO\\User"), "User");
        assert_eq!(account_name("User"), "User");
    }

    /// RFC 3079 §3.5.3. Its SendStartKey128 is derived with IsServer TRUE
    /// (§3.3), so it is the server's send key: the client's receive key.
    #[test]
    fn mppe_keys_match_rfc_3079() {
        let nt_response =
            arr::<24>("82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF");
        let password_hash_hash = hash_nt_password_hash(&nt_password_hash("clientPass"));
        assert_eq!(
            *password_hash_hash,
            arr::<16>("41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F")
        );
        assert_eq!(
            *master_key(&password_hash_hash, &nt_response),
            arr::<16>("FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31")
        );

        let server = mppe_keys("clientPass", &nt_response, true);
        let client = mppe_keys("clientPass", &nt_response, false);
        let rfc_send_start_key = arr::<16>("8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB");
        assert_eq!(*server.send, rfc_send_start_key);
        assert_eq!(*client.receive, rfc_send_start_key);
        assert_eq!(*client.send, *server.receive);
    }

    /// sstp-client's MPPE test: the client's master keys from a password and
    /// the NT-Response it sent.
    #[test]
    fn mppe_keys_match_sstp_clients_vector() {
        let vectors = crate::kat::vectors("sstp");
        for case in crate::kat::cases(&vectors, "mppe") {
            let nt_response: [u8; 24] = crate::kat::hex(&case["nt_response"]).try_into().unwrap();
            let keys = mppe_keys(crate::kat::text(&case["password"]), &nt_response, false);
            assert_eq!(keys.send.to_vec(), crate::kat::hex(&case["send_key"]));
            assert_eq!(keys.receive.to_vec(), crate::kat::hex(&case["recv_key"]));
        }
    }

    /// sstp-client's Compound MAC tests, one of them Windows' own
    /// computation from a capture. The HLAK is `send | receive` for 16-octet
    /// MPPE keys and the first 32 octets of the key material otherwise
    /// (EAP-TLS's MSK), as [MS-SSTP] §3.2.5.2.2 says.
    #[test]
    fn the_compound_mac_matches_sstp_clients_vectors() {
        let vectors = crate::kat::vectors("sstp");
        for case in crate::kat::cases(&vectors, "binding") {
            let send = crate::kat::hex(&case["send_key"]);
            let receive = crate::kat::hex(&case["recv_key"]);
            let mut hlak = [0u8; 32];
            if send.len() == 16 {
                hlak[..16].copy_from_slice(&send);
                hlak[16..].copy_from_slice(&receive);
            } else {
                hlak.copy_from_slice(&send[..32]);
            }
            let hash = match crate::kat::text(&case["hash"]) {
                "sha1" => BindingHash::Sha1,
                _ => BindingHash::Sha256,
            };
            assert_eq!(
                compound_mac(&hlak, hash, &crate::kat::hex(&case["call_connected"])),
                crate::kat::hex(&case["compound_mac"]),
                "{}",
                crate::kat::text(&case["origin"])
            );
        }
    }

    /// A Call Connected message with its MAC field zeroed, as the binding
    /// computes over. Not a vector: the vectors are in the KAT fixture.
    #[test]
    fn the_cmk_length_is_little_endian() {
        // Planting `to_be_bytes` in compound_mac_key changes this value;
        // the KAT test is what pins it to the references.
        let hlak = [7u8; 32];
        let key = hmac::Key::new(hmac::HMAC_SHA256, &hlak);
        let mut context = hmac::Context::with_key(&key);
        context.update(CMK_SEED);
        context.update(&[32, 0, 1]);
        assert_eq!(
            compound_mac_key(&hlak, BindingHash::Sha256).as_ref(),
            context.sign().as_ref()
        );
    }
}
