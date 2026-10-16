#[derive(Debug, Clone)]
pub struct ShadowTlsHmac {
    context: aws_lc_rs::hmac::Context,
}

impl ShadowTlsHmac {
    pub fn new(key: &aws_lc_rs::hmac::Key) -> Self {
        Self {
            context: aws_lc_rs::hmac::Context::with_key(key),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn digest(&self) -> [u8; 4] {
        let tag = self.context.clone().sign();
        let mut out = [0u8; 4];
        out.copy_from_slice(&tag.as_ref()[0..4]);
        out
    }

    pub fn finalized_digest(self) -> [u8; 4] {
        let tag = self.context.sign();
        let mut out = [0u8; 4];
        out.copy_from_slice(&tag.as_ref()[0..4]);
        out
    }
}

/// Constant-time comparison of two Shadow-TLS HMAC tags.
///
/// The tags authenticate the peer, so a data-dependent (short-circuiting)
/// comparison would leak, through timing, how many leading bytes matched -
/// enough to forge a tag byte by byte and defeat the anti-probing check.
#[inline]
pub fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// SHA256(password), ready to take the ServerRandom: the key the server XORs
/// over the handshake server's encrypted records, so a passive observer
/// cannot match them against the decoy's real traffic. Both ends build it.
#[derive(Clone)]
pub struct ShadowTlsXorContext(aws_lc_rs::digest::Context);

impl std::fmt::Debug for ShadowTlsXorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ShadowTlsXorContext]")
    }
}

impl ShadowTlsXorContext {
    pub fn new(password: &[u8]) -> Self {
        let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        context.update(password);
        Self(context)
    }

    /// SHA256(password ‖ server_random), applied cyclically from the first
    /// byte of each record's payload.
    pub fn key(&self, server_random: &[u8]) -> Vec<u8> {
        let mut context = self.0.clone();
        context.update(server_random);
        context.finish().as_ref().to_vec()
    }
}
