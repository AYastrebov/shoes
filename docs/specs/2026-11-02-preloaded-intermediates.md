# Preloaded intermediates for servers that send a short chain

Written 2026-11-02 against `mobile` at `713a8ec` (v0.9.4).

## Problem

A TLS server is meant to send its certificate followed by the
intermediates up to a root (RFC 8446 §4.4.2: the chain "SHOULD" be
complete, the root may be left out). Some do not. A Keenetic router's
OpenConnect server sends its Let's Encrypt leaf alone; the SSTP server on
the same router, with a certificate from the same issuer, sends the leaf,
YR1 and the cross-signed Root YR. The leaf is issued by YR1, which chains
to ISRG Root YR, which is not yet in any root program and is reached
through its cross-sign by ISRG Root X1.

webpki builds a path only from the certificates the server sent plus the
trust anchors, so every client verification of that OpenConnect server
failed with `InvalidCertificate(UnknownIssuer)`, although the certificate
is valid. The only way through was `verify: false` with a pin, and a Let's
Encrypt pin breaks at every renewal, about every 60 days. Browsers do not
see the defect: Firefox preloads every intermediate in the CCADB, and
Chrome and Windows fetch a missing one through the leaf's Authority
Information Access URL.

## Scope

In:

- Ship Let's Encrypt's intermediates in the binary, and retry a chain that
  failed with `UnknownIssuer` with them added after the server's own.
- Every client that verifies through webpki: `create_client_config`
  (TLS, QUIC, SSTP, OpenConnect, NaiveProxy and the rest), with and without
  `server_fingerprints`, and `create_dns_client_config` (DoT, DoH).

Out:

- AIA fetching. It makes a plain HTTP request to the CA in the middle of
  a handshake, which leaks the destination to the CA and the network,
  needs a socket the mobile builds must protect from their own tunnel, and
  waits on a third party. A fixed set covers the CA this was seen with.
- Other CAs' intermediates. The CCADB lists about 2,000; Firefox ships
  them, but at roughly 1.5 KB each that is 3 MB, well past the mobile
  budget (`mobile-size-baseline.txt` allows 2%). Add a CA's when a server
  is seen to need it.
- Roots. The set adds no trust anchor: a chain must still end at a root in
  `webpki-roots`, and Root YR and Root YE stay untrusted except through
  their cross-signs, as the server's own full chain would have them.

## The set

From <https://letsencrypt.org/certificates/>, downloaded 2026-11-02:

| Certificates | Issuer | Valid until |
| --- | --- | --- |
| YR1, YR2, YR3 | ISRG Root YR | 2028-09-02 |
| YE1, YE2, YE3 | ISRG Root YE | 2028-09-02 |
| Root YR (cross-sign) | ISRG Root X1 | 2032-09-02 |
| Root YE (cross-sign) | ISRG Root X2 | 2032-09-02 |
| R10 to R14 | ISRG Root X1 | 2027-03-12 |
| E5 to E9 | ISRG Root X2 | 2027-03-12 |

YR3 and YE3 are Let's Encrypt's backups. The X-generation E cross-signs
by X1 are left out: `webpki-roots` holds X2. The self-signed Root YR and
Root YE are left out: they are roots, and not trusted ones. Each file was
checked with `openssl verify` against the system store, and YR1 is
byte-identical to what the Keenetic leaf's AIA URL serves. 18 DER files,
19 KB.

## Verification

`PreloadingVerifier` wraps the `WebPkiServerVerifier`:

1. Verify the chain exactly as the server sent it. Any verdict other than
   `UnknownIssuer` (success, a wrong name, an expired leaf, a bad
   signature) is returned as it is.
2. On `UnknownIssuer`, verify again with the preloaded set appended after
   the server's intermediates, and return that verdict. The server's come
   first because path building tries candidates in order.

A server that sends its chain never reaches step 2, so its verification
is what it was before. The verifier is built once (`get_webpki_verifier`)
and shared, as the root store already was.

## Error handling

A chain still incomplete after the retry fails with the retry's error,
which is `UnknownIssuer` again: the message the user would have seen
anyway. A completed chain logs at debug that the server's chain was
short, so an operator can tell why a pin-free connection works here and
not in a strict client.

## Testing

- Unit, with an `rcgen` root, intermediate and leaf: a leaf sent alone
  fails under plain webpki and verifies with the intermediate preloaded;
  a complete chain verifies with nothing preloaded; a wrong name is still
  a name error after the retry; a leaf from a CA nobody preloaded still
  fails.
- Every preloaded certificate is signed by another in the set or by a
  root in `webpki-roots`, matched by subject and checked by signature
  with `x509-parser`, so a corrupt or mistaken file fails the suite.
- Shown to fail: the retry disabled turns the first and third red; the
  Root YR cross-sign replaced by another file turns the chain test red
  ("YR1 does not chain to a compiled-in root").
- Live, `tests/live_socks.rs` against the user's Keenetic OpenConnect
  server with no pin and `verify` left on: all four checks pass. The same
  config on v0.9.4 fails all four with `UnknownIssuer`.

## Upkeep

Let's Encrypt announces new intermediates ahead of use. When it does, add
them here; an expired one needs no removal, since it can no longer
complete a chain, but drop it at the next refresh. Recorded in
`ROADMAP.md`, "Recorded debt".
