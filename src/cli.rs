//! What the `shoes` binary needs from the library beyond [`crate::control`]:
//! its key generators and the worker count.

/// A REALITY keypair, base64url as configs carry it: `(private, public)`.
pub fn generate_reality_keypair() -> std::io::Result<(String, String)> {
    crate::reality::generate_keypair()
}

/// The key length of a Shadowsocks 2022 cipher named without its
/// `2022-blake3-` prefix, or `None` for a name that is not one.
pub fn shadowsocks_2022_key_len(base_cipher: &str) -> Option<usize> {
    crate::shadowsocks::ShadowsocksCipher::try_from(base_cipher)
        .ok()
        .map(|cipher| cipher.key_len())
}

/// A random VLESS/VMess user id.
pub fn generate_user_id() -> String {
    crate::uuid_util::generate_uuid()
}

/// Set the worker count; the first value set wins.
pub fn set_num_threads(num_threads: usize) {
    crate::thread_util::set_num_threads(num_threads);
}

/// The worker count, or the default when none was set.
pub fn get_num_threads() -> usize {
    crate::thread_util::get_num_threads()
}
