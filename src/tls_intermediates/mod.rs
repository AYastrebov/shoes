//! Intermediate certificates shipped with the binary, for servers that leave
//! theirs out of the handshake.
//!
//! A server is meant to send its certificate followed by the intermediates
//! up to a root, and most do. Some do not: a Keenetic router's OpenConnect
//! server sends its Let's Encrypt leaf alone, while the SSTP server on the
//! same router sends the whole chain. Browsers fill such a gap from
//! intermediates they already hold (Firefox preloads every intermediate in
//! the CCADB) or fetch through the leaf's AIA URL; webpki does neither, so
//! the handshake failed with `UnknownIssuer` although the certificate is
//! valid. See `docs/specs/2026-11-02-preloaded-intermediates.md`.
//!
//! The set is Let's Encrypt's: every intermediate that can still issue, and
//! the cross-signs that connect its new roots to the ones
//! `webpki-roots` holds. It adds no trust: a chain must still end at a
//! compiled-in root, and a preloaded certificate only stands in for one the
//! server could have sent itself. Downloaded from
//! <https://letsencrypt.org/certificates/> on 2026-11-02; each was checked
//! to chain to ISRG Root X1 or X2.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};

/// Let's Encrypt's intermediates and cross-signs, by name. The X1/X2
/// generation (R10-R14, E5-E9) expires on 2027-03-12, the Y generation on
/// 2028-09-02; an expired one simply never completes a chain again.
pub(crate) static LETS_ENCRYPT: [(&str, CertificateDer<'static>); 18] = [
    // Generation Y, issuing since 2025, under roots not yet in trust stores.
    (
        "YR1",
        CertificateDer::from_slice(include_bytes!("int-yr1.der")),
    ),
    (
        "YR2",
        CertificateDer::from_slice(include_bytes!("int-yr2.der")),
    ),
    (
        "YR3",
        CertificateDer::from_slice(include_bytes!("int-yr3.der")),
    ),
    (
        "YE1",
        CertificateDer::from_slice(include_bytes!("int-ye1.der")),
    ),
    (
        "YE2",
        CertificateDer::from_slice(include_bytes!("int-ye2.der")),
    ),
    (
        "YE3",
        CertificateDer::from_slice(include_bytes!("int-ye3.der")),
    ),
    // How generation Y reaches a root webpki-roots holds.
    (
        "Root YR by ISRG Root X1",
        CertificateDer::from_slice(include_bytes!("root-yr-by-x1.der")),
    ),
    (
        "Root YE by ISRG Root X2",
        CertificateDer::from_slice(include_bytes!("root-ye-by-x2.der")),
    ),
    // Generation X, directly under ISRG Root X1 and X2.
    ("R10", CertificateDer::from_slice(include_bytes!("r10.der"))),
    ("R11", CertificateDer::from_slice(include_bytes!("r11.der"))),
    ("R12", CertificateDer::from_slice(include_bytes!("r12.der"))),
    ("R13", CertificateDer::from_slice(include_bytes!("r13.der"))),
    ("R14", CertificateDer::from_slice(include_bytes!("r14.der"))),
    ("E5", CertificateDer::from_slice(include_bytes!("e5.der"))),
    ("E6", CertificateDer::from_slice(include_bytes!("e6.der"))),
    ("E7", CertificateDer::from_slice(include_bytes!("e7.der"))),
    ("E8", CertificateDer::from_slice(include_bytes!("e8.der"))),
    ("E9", CertificateDer::from_slice(include_bytes!("e9.der"))),
];

/// A webpki verifier that retries a chain it could not complete, with the
/// preloaded intermediates added after the ones the server sent.
///
/// Only `UnknownIssuer` is retried: every other verdict, a wrong name or an
/// expired leaf among them, is the server's own and is returned as it was.
/// A server that sends its chain never reaches the preload, so its
/// verification is exactly what it was before.
#[derive(Debug)]
pub(crate) struct PreloadingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    preloaded: Vec<CertificateDer<'static>>,
}

impl PreloadingVerifier {
    pub(crate) fn lets_encrypt(inner: Arc<WebPkiServerVerifier>) -> Self {
        Self::with(inner, LETS_ENCRYPT.iter().map(|(_, der)| der.clone()))
    }

    fn with(
        inner: Arc<WebPkiServerVerifier>,
        preloaded: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Self {
        Self {
            inner,
            preloaded: preloaded.into_iter().collect(),
        }
    }
}

impl ServerCertVerifier for PreloadingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
                if !self.preloaded.is_empty() =>
            {
                // The server's own intermediates first: path building tries
                // candidates in order, and theirs are the ones it meant.
                let mut completed = Vec::with_capacity(intermediates.len() + self.preloaded.len());
                completed.extend(intermediates.iter().cloned());
                completed.extend(self.preloaded.iter().cloned());
                let verified = self.inner.verify_server_cert(
                    end_entity,
                    &completed,
                    server_name,
                    ocsp_response,
                    now,
                )?;
                log::debug!(
                    "TLS: the server sent an incomplete certificate chain; completed it from the preloaded intermediates"
                );
                Ok(verified)
            }
            verdict => verdict,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    fn ca_params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    /// A root, an intermediate under it, and a leaf for `vpn.test` under
    /// the intermediate: the shape of a Let's Encrypt chain, with keys the
    /// test holds.
    struct Pki {
        root: CertificateDer<'static>,
        intermediate: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
    }

    fn pki(ca: &str) -> Pki {
        let root = CertifiedIssuer::self_signed(
            ca_params(&format!("{ca} Root")),
            KeyPair::generate().unwrap(),
        )
        .unwrap();
        let intermediate = CertifiedIssuer::signed_by(
            ca_params(&format!("{ca} Intermediate")),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["vpn.test".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &intermediate)
            .unwrap();
        Pki {
            root: root.der().clone(),
            intermediate: intermediate.der().clone(),
            leaf: leaf.der().clone(),
        }
    }

    fn webpki(root: &CertificateDer<'static>) -> Arc<WebPkiServerVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap()
    }

    fn verify(
        verifier: &dyn ServerCertVerifier,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &'static str,
    ) -> Result<ServerCertVerified, Error> {
        verifier.verify_server_cert(
            leaf,
            intermediates,
            &ServerName::try_from(name).unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn a_leaf_sent_without_its_intermediate_verifies_through_the_preload() {
        let pki = pki("Test");
        let plain = webpki(&pki.root);
        assert!(matches!(
            verify(plain.as_ref(), &pki.leaf, &[], "vpn.test"),
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
        ));

        let preloading = PreloadingVerifier::with(plain, [pki.intermediate]);
        verify(&preloading, &pki.leaf, &[], "vpn.test").unwrap();
    }

    #[test]
    fn a_complete_chain_never_needs_the_preload() {
        let pki = pki("Test");
        let preloading = PreloadingVerifier::with(webpki(&pki.root), []);
        verify(&preloading, &pki.leaf, &[pki.intermediate], "vpn.test").unwrap();
    }

    #[test]
    fn the_preload_does_not_excuse_a_wrong_name() {
        let pki = pki("Test");
        let preloading = PreloadingVerifier::with(webpki(&pki.root), [pki.intermediate]);
        let error = verify(&preloading, &pki.leaf, &[], "other.test").unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_leaf_from_a_ca_nobody_preloaded_still_fails() {
        let trusted = pki("Trusted");
        let stranger = pki("Stranger");
        let preloading = PreloadingVerifier::with(webpki(&trusted.root), [trusted.intermediate]);
        assert!(matches!(
            verify(&preloading, &stranger.leaf, &[], "vpn.test"),
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
        ));
    }

    /// A preloaded certificate that a byte flip or a wrong download had
    /// broken would never complete a chain, silently. Each must be signed
    /// by another in the set or by a root webpki-roots holds, matched by
    /// subject and checked by signature.
    #[test]
    fn every_preloaded_certificate_chains_to_a_compiled_in_root() {
        use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

        let parsed: Vec<(&str, X509Certificate<'_>)> = LETS_ENCRYPT
            .iter()
            .map(|(name, der)| (*name, X509Certificate::from_der(der.as_ref()).unwrap().1))
            .collect();
        for (name, cert) in &parsed {
            let issuer = cert.issuer().as_raw();
            let in_set = parsed
                .iter()
                .find(|(other, c)| other != name && c.subject().as_raw() == issuer);
            let verified = if let Some((_, parent)) = in_set {
                cert.verify_signature(Some(parent.public_key())).is_ok()
            } else {
                webpki_roots::TLS_SERVER_ROOTS.iter().any(|anchor| {
                    // webpki-roots stores the values without their SEQUENCE
                    // header; the certificate's issuer has one.
                    issuer.ends_with(anchor.subject.as_ref())
                        && issuer.len() - anchor.subject.as_ref().len() <= 4
                        && SubjectPublicKeyInfo::from_der(&with_sequence_header(
                            anchor.subject_public_key_info.as_ref(),
                        ))
                        .is_ok_and(|(_, spki)| cert.verify_signature(Some(&spki)).is_ok())
                })
            };
            assert!(verified, "{name} does not chain to a compiled-in root");
        }
    }

    /// Prefixes DER content with a SEQUENCE tag and its length.
    fn with_sequence_header(content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = vec![0x30];
        match len {
            0..=0x7f => out.push(len as u8),
            0x80..=0xff => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }
}
