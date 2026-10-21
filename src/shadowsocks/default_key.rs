#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use md5::{Digest, Md5};

use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
pub struct DefaultKey {
    key_bytes: Box<[u8]>,
    key_len: usize,
}

impl DefaultKey {
    pub fn new(password: &str, key_len: usize) -> Self {
        Self {
            key_bytes: get_key_bytes(password, key_len),
            key_len,
        }
    }
}

const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];

struct SliceKeyType<'a>(&'a [u8]);

impl aws_lc_rs::hkdf::KeyType for SliceKeyType<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl ShadowsocksKey for DefaultKey {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let mut session_key = allocate_vec(self.key_len);
        aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
            .extract(&self.key_bytes)
            .expand(SS_SUBKEY_INFO, SliceKeyType(&self.key_bytes))
            .unwrap()
            .fill(&mut session_key)
            .unwrap();
        session_key.into_boxed_slice()
    }
}

fn get_key_bytes(key: &str, cipher_key_len: usize) -> Box<[u8]> {
    // TODO: This is the same as openssl::pkcs5::bytes_to_key.
    // Is it possible not to depend on the md5 crate when openssl is enabled?
    let key = key.as_bytes();
    let mut ret = vec![];
    let mut context = Md5::new();
    loop {
        context.update(key);
        let digest: [u8; 16] = context.finalize().into();
        ret.extend(digest.iter());
        if ret.len() >= cipher_key_len {
            break;
        }
        context = Md5::new();
        context.update(digest);
    }
    ret.truncate(cipher_key_len);
    ret.into_boxed_slice()
}

/// Against sing-shadowsocks (`tests/data/kat/shadowsocks`).
#[cfg(test)]
mod kat_tests {
    use super::*;
    use crate::kat::{cases, hex, number, text, vectors};

    #[test]
    fn evp_bytes_to_key_matches_the_reference() {
        let vectors = vectors("shadowsocks");
        for case in cases(&vectors, "evp_bytes_to_key") {
            let key_len = number(&case["key_len"]) as usize;
            assert_eq!(
                get_key_bytes(text(&case["password"]), key_len).to_vec(),
                hex(&case["key"]),
                "password {:?}, {key_len} bytes",
                case["password"]
            );
        }
    }

    #[test]
    fn the_ss_subkey_matches_the_reference() {
        let vectors = vectors("shadowsocks");
        for case in cases(&vectors, "hkdf_sha1_subkey") {
            let key_bytes = hex(&case["key"]).into_boxed_slice();
            let key = DefaultKey {
                key_len: key_bytes.len(),
                key_bytes,
            };
            assert_eq!(
                key.create_session_key(&hex(&case["salt"])).to_vec(),
                hex(&case["subkey"])
            );
        }
    }
}
