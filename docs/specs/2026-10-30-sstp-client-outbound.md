# SSTP client outbound

Design for dialling SSTP servers from shoes: Microsoft's Secure Socket
Tunneling Protocol, which carries PPP over HTTPS on port 443. Client only.
Like WireGuard and AmneziaWG, it is a layer-3 tunnel, so proxied TCP and UDP
cross it through shoes' userspace TCP/IP stack.

Written 2026-10-30 against `mobile` at `12a3fee` (v0.9.0 + 9). SSTP was
asked for. It is the first entry on the axis the roadmap calls "classic
enterprise VPN" ("Where we already compete"); OpenVPN and OpenConnect, which
sing-box 1.14 added, are not part of this document.

## Sources

Every wire detail below was read from these, not recalled. Each claim
cites where it came from.

| Source | Version read | Licence | Used for |
| --- | --- | --- | --- |
| [MS-SSTP] Secure Socket Tunneling Protocol | v20240423 (release of 2024-04-23) | Microsoft Open Specifications Promise | The protocol. Authoritative where the others disagree |
| [kittoku/Open-SSTP-Client](https://github.com/kittoku/Open-SSTP-Client) | `5f97511` (2026-08-15) | MIT | A complete userspace client on Android `VpnService`: SSTP, PPP, MS-CHAPv2, crypto binding. The closest analogue to this design |
| [sstp-project/sstp-client](https://gitlab.com/sstp-project/sstp-client) | 1.0.20, `dd24312` (2024-08-02) | GPL-2.0-or-later | The Linux client, which runs `pppd` for PPP. Behaviour and test vectors only, no code |
| [SoftEtherVPN/SoftEtherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN) | `5b5f799` (2026-10-30) | Apache-2.0 | An SSTP server that runs in userspace; the easiest live peer |
| [accel-ppp/accel-ppp](https://github.com/accel-ppp/accel-ppp) | `d80cdc6` (2026-10-29) | GPL-2.0-or-later | An SSTP server that verifies crypto binding. Behaviour only, no code |
| RFC 1661 (PPP), 1332 (IPCP), 1877 (IPCP DNS), 1334 (PAP), 2759 (MS-CHAPv2), 3079 (MPPE keys), 5072 (IPv6CP) | as published | — | PPP and authentication. RFC 2759 §9.2 and RFC 3079 §3.5.3 print vectors |

The GPL references contribute behaviours, reasons and published test data.
No code is copied from them. Open-SSTP-Client is MIT, so its structure may
be followed, and is where noted.

## Problem

A user whose VPN is an SSTP server cannot reach it through shoes. That
server might be Windows RRAS, a MikroTik router, a SoftEther or accel-ppp
deployment, or a home router (Keenetic ships an SSTP server). SSTP's
appeal is that it is HTTPS on 443 and crosses networks that block
WireGuard's UDP and PPTP's GRE. On mobile, the alternatives are a second VPN
app, which cannot run beside shoes, or nothing.

## Scope

**In scope:**
- A `TerminalConnector` that holds one SSTP session per configured hop and
  carries TCP and UDP through the existing smoltcp stack.
- MS-CHAPv2 and PAP authentication.
- Crypto binding with SHA-256 or SHA-1.
- IPv4 through IPCP, with the server's DNS servers recorded.
- Certificate pinning through the existing `server_fingerprints` setting.
- Recovery after a network change.

**A server is out of scope.** Testing pays for that with an in-process
server double, described under Testing.

**Out of scope.** Each item is refused when it is reached, by config
validation where it is a setting and by a named error where the server
asks for it. None is silently ignored:

| Feature | Where it is refused | Why it is out |
| --- | --- | --- |
| EAP in any form (EAP-MSCHAPv2, EAP-TLS, PEAP) | LCP: we Configure-Nak an EAP proposal with MS-CHAPv2, and fail naming EAP if the server insists | A second state machine for the same keys. SoftEther proposes EAP first and moves to MS-CHAPv2 when a client refuses it (`src/Cedar/Proto_PPP.c:946-961`). Whether a given Windows RRAS policy allows MS-CHAPv2 beside EAP is a live-check item. Open-SSTP-Client supports EAP-MSCHAPv2 (`client/ppp/auth/EAPMSAuthClient.kt`), so it is the reference if this is ever wanted |
| MS-CHAPv1, CHAP-MD5 | as above | Neither produces the MPPE keys crypto binding needs from MS-CHAPv2, and both are weaker |
| IPv6 (IPv6CP) | An IPv6CP Configure-Request from the server gets an LCP Protocol-Reject (RFC 1661 §5.7) | IPv6CP negotiates only an interface identifier (RFC 5072 §4.1). A routable address then needs SLAAC or DHCPv6 over the link, and smoltcp implements neither. The same gap as `shoesd`'s v6 handling, from the other side |
| An HTTP proxy in front of the server (`CONNECT`) | config: no such field | [MS-SSTP] §1.3 points at [SSLPROXY] for it. A proxy hop would make this a chained outbound, which a `TerminalConnector` is not (`src/tcp/terminal_connector.rs:10`) |
| TLS client certificates (`key`, `cert`) | config validation | [MS-SSTP] §2.1: the server MAY authenticate the client by TLS. No known deployment depends on it, and PPP authentication is still required |
| Bypassing PPP authentication (`ClientBypassHLAuth` and its cookie) and the `tenantid` query variable | config: no such field | [MS-SSTP] §3.2.4.1. Both depend on an implementation-specific management layer on the server |
| Being any hop but the only one | config validation, as for Hysteria2 and TUIC | `src/tcp/terminal_connector.rs:10` |
| TLS 1.0 and 1.1, and TLS 1.2 without ECDHE | not refusable: rustls does not implement them | rustls has neither. A server that offers nothing else fails the handshake with rustls's own error. Recorded as a risk, not worked around |

## What the references do

**[MS-SSTP] (the protocol).**
- **Transport (§2.1, §3.2.4.1, §4.1).** One TCP connection. TLS with
  server authentication: the client SHOULD check the name and MUST check
  for the `id-kp-serverAuth` or `anyExtendedKeyUsage` EKU. Then one HTTP/1.1
  request with method `SSTP_DUPLEX_POST`, URI
  `/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/`,
  `Content-Length: 18446744073709551615`, `Host`, and an `SSTPCORRELATIONID`
  header carrying a fresh GUID. The server answers `200` with the same
  content length, and the connection becomes a duplex stream of SSTP
  packets.
- **Packets (§2.2.1 to §2.2.3).** A 4-byte header:
  - version `0x10`;
  - a byte whose low bit `C` marks a control packet;
  - a 16-bit field whose low 12 bits are the length of the whole packet,
    header included.

  So an SSTP packet is at most 4095 bytes. A data packet's body is one PPP
  frame, and that frame has no HDLC flag, escaping or FCS. A control packet's
  body is a 16-bit message type, a 16-bit attribute count, and attributes.
  Each attribute is a reserved byte, an id, and a 12-bit length that
  includes its own 4-byte header (§2.2.4).
- **Negotiation (§3.2.5.3.2, §3.2.7.1).**
  1. The client sends Call Connect Request (14 bytes; one Encapsulated
     Protocol ID attribute, PPP = `0x0001`).
  2. The server answers Call Connect Ack (48 bytes). It carries a Crypto
     Binding Request attribute: a hash bitmask (bit 0 SHA-1, bit 1 SHA-256)
     and a 32-byte nonce.
  3. The client picks SHA-256 when both are offered (§1.7) and starts PPP.
     PPP control frames may flow from the Ack onward. PPP data frames may
     flow only after the client has sent Call Connected.
  4. The client sends Call Connected (112 bytes) once PPP authentication
     succeeds. It carries the nonce, the hash of the server certificate,
     and the Compound MAC.
- **Crypto binding (§3.2.5.2).**
  - HLAK is 32 bytes. For MS-CHAPv2 it is `MasterSendKey | MasterReceiveKey`
    from RFC 3079 §3, as the client sees them. It is 32 zero bytes when
    the method produces no keys, which is the case for PAP.
  - `CMK = PRF+(HLAK, "SSTP inner method derived CMK", LEN)`, the first
    `LEN` octets, with `T1 = HMAC(HLAK, S | LEN | 0x01)`. LEN is a 16-bit
    integer encoded **little-endian**: 20 for SHA-1, 32 for SHA-256.
  - The Compound MAC is `HMAC(CMK, Call Connected)`, computed over the
    whole 112-byte message with the MAC and padding fields zeroed.
  - The Cert Hash is SHA-1 (20 bytes plus 12 bytes of zero padding) or
    SHA-256 (32 bytes) of the server's certificate.
  - "Implementations MUST support the Crypto Binding feature."
- **Timers (§3.1.2, §3.2.2.1).**
  - Hello: after 60 s with nothing received, send an Echo Request. If
    nothing arrives in the next 60 s, abort without sending Call Abort.
  - Negotiation: 60 s.
  - Abort: 3 s, then 1 s.
  - Disconnect: 5 s, then 1 s.
- **Sizes (§3.1.5.2).** "The maximum receive unit (MRU) exchanged for SSTP
  is 4091 bytes, which is 4095 – sizeof(SSTP_HEADER)." Windows defaults to
  an MTU of 1400 and a PPP adapter MRU of 1614.

**Open-SSTP-Client (MIT, a full userspace client).**
- **HTTP request.** `terminal/SSLTerminal.kt:284-287` builds it, braces
  around the correlation GUID included.
- **Crypto binding.** `client/SstpClietnt.kt:179-212`.
  - The CMK is built as `seed | LEN | 0x01` and HMACed once. One block of
    PRF+ always covers LEN, because LEN is at most one hash long.
  - LEN is `0x1400` or `0x2000`, written through a big-endian
    `ByteBuffer`. That is the little-endian 20 and 32 pre-swapped
    (`:42`, `:49`, `:56`).
  - PAP gets a zero HLAK (`:195`).
- **MS-CHAPv2.**
  - The NT-Response and the authenticator check are in
    `client/ppp/auth/MSCHAPV2Client.kt:79-145`.
  - The HLAK derivation, with RFC 3079's magic constants spelled out, is
    `:148-208`. For the client, `MasterSendKey` takes the "send key" magic.
  - The authenticator response is compared with `contentEquals` (`:145`),
    which is not constant-time.
- **LCP.** `client/ppp/LCPClient.kt:31-149`.
  - It rejects every option it does not know, ACFC and PFC included, so it
    always sends and expects `FF 03`.
  - It Configure-Naks a server MRU smaller than its own MTU.
  - It proposes only an MRU, defaulting to 1500 (`configuration.kt:4-9`).
    It sends no Magic-Number.
  - It Configure-Naks an unacceptable auth proposal with its preferred one.
- **Outbound data path.** `io/OutgoingManager.kt:31-53` is the one
  performance idea worth taking whole.
  - One coroutine drains every IP packet already queued into one buffer
    of the TLS engine's application-buffer size, about 16 KiB.
  - It sends that buffer with one TLS write, so a burst of packets costs
    one TLS record instead of one each.
  - The packet reader double-buffers two MTU-sized buffers, so it
    allocates nothing per packet (`:56-74`).
- **Receive buffer.** One buffer of application-buffer size plus
  `MAX_MRU + 8` (`io/incoming/IncomingManager.kt:51`). Echo every 20 s on
  both layers (`:47-48`).
- **Retransmission and timeouts.** PPP retransmits every 3 s, up to 10
  times (`client/ppp/ConfigClient.kt:19-21`), which is RFC 1661's Restart
  timer and Max-Configure. The SSTP request times out after 60 s
  (`client/SstpClietnt.kt:37-39`).

**sstp-client (GPL; behaviour only).**
- **PPP runs in `pppd` on a pty.** It speaks async HDLC, so every frame is
  HDLC-decoded on the way in and HDLC-encoded on the way out, byte by byte,
  with an FCS table (`src/sstp-pppd.c:339`, `:476`; `src/sstp-fcs.c`).
  That is a per-byte cost on the data path that a userspace PPP does not
  pay. SSTP itself carries no HDLC.
- **One `SSL_write` per frame** (`src/sstp-stream.c:649`), so one TLS
  record per packet.
- **The CMK.** It is HMACed once, with LEN written as two bytes `len, 0`.
  The comment says "LEN must be encoded in little endian format"
  (`src/sstp-cmac.c:177-190`).
- **Test vectors.**
  - Two Call Connected messages with their MPPE keys and the expected
    Compound MAC, for SHA-1 and SHA-256 (`src/sstp-cmac.c:329-545`).
  - An MPPE send and receive key pair derived from a known password,
    challenge and NT-Response (`src/sstp-chap.c:351-420`).

**SoftEther (Apache; a userspace server, so the easiest live peer).**
- **Crypto binding is not checked.** It offers SHA-256 only
  (`src/Cedar/Proto_SSTP.c:226`). On Call Connected it marks the session
  established without checking the MAC (`:250-259`). A client that gets
  binding wrong still works against SoftEther.
- **It is the chattiest peer.** It sends an SSTP Echo Request every 2.5 to
  4.8 s (`Proto_SSTP.c:428`, `Proto_SSTP.h:19-20`) and drops the session
  after 20 s with nothing received (`Proto_SSTP.h:21`).
- **MRU.** It caps the PPP MRU at 1500 and Configure-Naks anything larger
  down to it (`Proto_PPP.h:49-51`, `Proto_PPP.c:1694-1701`).
- **Usernames.** It strips an NT domain before the MS-CHAPv2 challenge
  hash, as RFC 2759 §4 says (`Proto_PPP.c:4401`). It reads a `HUB\user`
  prefix as the virtual hub to log into (`Proto_PPP.c:4226-4255`).
- **The HTTP request.** It matches the method case-insensitively and the
  URI exactly (`Protocol.c:5906`, `:5911`).

**accel-ppp (GPL; behaviour only).**
- **It checks crypto binding for real.** It accepts SHA-1 and SHA-256
  (`accel-pppd/ctrl/sstp/sstp.c:191`). It compares the Cert Hash against
  its own certificate's when one is configured (`:1737-1756`). It
  recomputes the Compound MAC from its server-side HLAK and aborts on a
  mismatch (`:1760-1792`). A Call Connected that arrives before its own
  authentication finished is deferred, not refused (`:1761`). This is the
  peer that proves binding correct, as Windows would.
- **Defaults.** PPP MTU 1452 (`:180`). Hello 60 s, abort 3 s and 1 s,
  disconnect 5 s and 1 s (`sstp_prot.h:17-21`). Maximum packet 4095
  (`sstp_prot.h:11`).
- **Usernames.** Its MS-CHAPv2 hashes the name exactly as received, with
  no domain stripped (`accel-pppd/auth/auth_mschap_v2.c:281`).

### Where the references disagree, and what this follows

- **The username in the MS-CHAPv2 challenge hash.**
  - RFC 2759 §4 and SoftEther hash only the account name: `johndoe` for
    `BIGCO\johndoe`. accel-ppp hashes what it received, and Open-SSTP-Client
    hashes what it sends (`MSCHAPV2Client.kt:79`).
  - **This follows the RFC**, because Windows, the server SSTP is defined
    by, is what the RFC describes.
  - A name with no backslash hashes identically everywhere. A `DOMAIN\user`
    name against accel-ppp is a live-check item.
- **Magic-Number.** Open-SSTP-Client sends none. RFC 1661 §6.4 defines it
  to detect looped-back links, says to choose it "in the most random
  manner possible", and has Echo-Replies carry it. **This sends a random
  one.** No reference refuses one.
- **ACFC and PFC.** This rejects both, as Open-SSTP-Client does: every frame
  carries `FF 03` and a two-byte protocol. RFC 1661 §6.5 says compressed
  fields "MUST NOT be transmitted unless this Configuration Option has been
  negotiated", so a peer that sends them unasked is wrong. On receipt this
  accepts a frame without `FF 03` or with a one-byte protocol anyway.
  Tolerating it costs one comparison, and refusing it would turn a peer's
  bug into a dead tunnel.
- **The hello interval.** Open-SSTP-Client uses 20 s, SoftEther 2.5 to 4.8 s,
  and [MS-SSTP] and accel-ppp 60 s. **This uses 60 s.** It answers the
  server's echoes regardless, and the 60 s only bounds how long a dead path
  goes unnoticed when nothing else is flowing. A network change is
  reported to shoes directly (see Architecture), so the interval is not
  what recovery waits on. On mobile, every wakeup is battery.

## Protocol summary

```
TCP connect ──► TLS handshake (server authenticated; leaf hash kept)
  ──► "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1"
  ◄── "HTTP/1.1 200 ..."
  ──► Call Connect Request
  ◄── Call Connect Ack (hash bitmask, nonce)
  ──► LCP Configure-Request (MRU, Magic-Number)  ◄─► server's LCP Configure-Request
  ◄── CHAP Challenge (MS-CHAPv2)  ──► Response  ◄── Success "S=<authenticator>"
                                      (or PAP Authenticate-Request ◄── Ack)
  ──► Call Connected (nonce, cert hash, Compound MAC)  ┐ one write
  ──► IPCP Configure-Request (0.0.0.0, DNS 0.0.0.0)    ┘
  ◄── IPCP Configure-Nak (assigned address, DNS)  ──► Configure-Request  ◄── Ack
  ◄─► IP packets as PPP protocol 0x0021
```

Frames this client emits:

| Layer | Bytes |
| --- | --- |
| SSTP data packet | `10 00 LL LL` + PPP frame, where `LLLL` = `0x0fff & (4 + frame length)` |
| PPP frame | `FF 03` + protocol (2 bytes) + information |
| Protocols | LCP `C021`, PAP `C023`, CHAP `C223` (MS-CHAPv2 is algorithm `0x81`), IPCP `8021`, IPv4 `0021`. Anything else is answered with LCP Protocol-Reject |
| LCP options sent | MRU (1), Magic-Number (5) |
| LCP options accepted from the server | MRU, Auth-Protocol (3, if it names a configured method), Magic-Number. Others are Configure-Rejected |
| IPCP options sent | IP-Address (3), Primary DNS (129), Secondary DNS (131), from 0.0.0.0. A Configure-Reject of the DNS options drops them, which is how a server without DNS answers |
| IPCP options accepted | IP-Address. IP-Compression (VJ, 2) is Configure-Rejected |

The PPP automaton is RFC 1661 §4's, reduced to what a client that never
renegotiates needs. Configure-Request is retransmitted every 3 s, at most
10 times. Terminate-Request, Echo-Request and Code-Reject are answered.
Renegotiation after Opened, which the server starts by sending a new
Configure-Request, ends the session instead of being followed. No server
in the references renegotiates, and following one would mean changing the
MTU of a live smoltcp interface.

MS-CHAPv2 follows RFC 2759 §8 exactly:
- NtPasswordHash is MD4 of the password as UTF-16LE.
- ChallengeResponse uses three DES keys from the 21-byte padded hash.
- The 16-byte Peer-Challenge comes from the OS RNG.
- The username in the Response's Name field is sent as configured. Only
  the challenge hash strips `DOMAIN\`.
- The Success message's `S=` value, 40 hex digits, is checked with
  `subtle::ConstantTimeEq` before anything else happens. A server that
  cannot prove it knows the password is refused (§8.8). This is the mutual
  half of MS-CHAPv2, and the reason to prefer it over PAP.
- A Failure message's `E=` code is parsed into the error (691, 648, …).
  `R=1` (retry allowed) is not acted on: there are no other credentials to
  try.

MPPE keys follow RFC 3079 §3.3–3.4 with 16-byte keys:
- `MasterKey = GetMasterKey(PasswordHashHash, NT-Response)`.
- `MasterSendKey = GetAsymmetricStartKey(MasterKey, 16, send = true, server = false)`.
- `MasterReceiveKey` is the same with `send = false`.

The client's HLAK is `MasterSendKey | MasterReceiveKey`, per [MS-SSTP]
§3.2.5.2.2.

## Architecture

### Where it plugs in

SSTP owns its transport and multiplexes every proxied connection over one
authenticated session. It is therefore a `TerminalConnector`, the shape
Hysteria2, TUIC and AmneziaWG take, and never a `TcpClientHandler`. A
handler is built per connection, and a PPP authentication per connection
is absurd.
- `ClientProxyConfig::Sstp` joins `owns_transport()`
  (`src/config/types/client.rs:877-885`).
- `build_terminal_connector` (`src/tcp/chain_builder.rs:159`) gets an arm.
- Validation rejects SSTP anywhere but alone in a chain, as it does for the
  others.

### The shared stack

AmneziaWG's `VirtualNetStack` (`src/amneziawg/netstack.rs:325`) already does
everything SSTP needs:
- it turns `ConnectTcp` and `ConnectUdp` requests into smoltcp sockets;
- it exchanges IP packets through two bounded `mpsc` channels;
- it backpressures instead of dropping when the outbound channel is full
  (`tx_budget`, `:66-113`).

Nothing in it is WireGuard-specific. It moves to `src/netstack/` with no
behaviour change, in a commit of its own. AmneziaWG imports it from there.
`outbound_offered`, which only AmneziaWG's liveness watchdog reads, stays
a constructor argument. SSTP passes a counter nobody reads.

The connector's lifecycle is AmneziaWG's (`src/amneziawg/connector.rs:145-258`):
- The session is built lazily, on the first connection.
- It is rebuilt when the previous one is dead.
- A failed build fails new connections fast for `REBUILD_COOLDOWN` (3 s,
  `:59`) instead of redialling and re-authenticating once per inbound
  connection.

`AmneziaWgConnector` has a few hundred lines of that machinery in
`ensure_initialized`. It is copied in shape, not generalised: two users do
not yet justify a trait. The third terminal connector to need it should
extract it.

### Network changes

`shoes_network_changed()` and its JNI twin call
`amneziawg::notify_network_change()` (`src/ffi/ios.rs:550`,
`src/ffi/android.rs:538`). That walks a registry of AmneziaWG endpoint
sockets (`src/amneziawg/endpoint.rs:34-60`).
- The registry moves to `src/network_change.rs` as
  `Weak<dyn NetworkChangeListener>` entries. AmneziaWG's `EndpointSocket`
  registers there, unchanged in behaviour, and the FFI calls the new
  function.
- An SSTP session registers too. On a change it marks itself dead and
  shuts its TCP connection down at once.
  - A UDP tunnel can rebind under its peer. A TCP connection cannot
    survive its interface going away, so the honest move is to stop now.
    Waiting for the 60 s hello timeout would leave the tunnel black-holed
    for up to two minutes.
  - The next connection rebuilds the session.
- Every flow through the old session ends with it. The new PPP session may
  have a different address, so the smoltcp sockets bound to the old one
  could not continue anyway. AmneziaWG keeps its flows across a rebind;
  SSTP cannot. CONFIG.md says so.

### Modules

`src/sstp/`. Each module has one purpose and its own tests:

| Module | Responsibility | I/O |
| --- | --- | --- |
| `packet.rs` | The SSTP codec: data and control packets, the four attributes, length checks. Encode and decode both | none |
| `ppp/frame.rs` | PPP frames and the LCP/IPCP/PAP/CHAP packet and option codecs | none |
| `ppp/negotiate.rs` | The reduced RFC 1661 automaton for LCP and IPCP, driven by frames and a clock | none |
| `auth.rs` | MS-CHAPv2 (response, authenticator check, Failure parsing) and PAP | none |
| `crypto.rs` | NtPasswordHash, MPPE master keys, HLAK, CMK, Compound MAC | none |
| `handshake.rs` | Drives TCP, TLS, HTTP, SSTP and PPP up to Opened IPCP, under one deadline. Returns the stream halves, the assigned address, the peer MRU and the DNS servers | yes |
| `session.rs` | The data path (two tasks, below), the hello timer, and teardown | yes |
| `connector.rs` | `TerminalConnector`, lifecycle, cooldown, network-change listener | yes |
| `testing.rs` | The in-process server double (Testing) | yes |

The codecs encode and decode, so the server double reuses them, as
`src/hysteria2/frame.rs` serves both of its directions. `negotiate.rs` takes
time as an argument, so retransmission is tested without waiting for it.

### TLS

The connector builds its `rustls::ClientConfig` with `create_client_config`
(`src/rustls_config_util.rs:13`), allowing TLS 1.2 and 1.3. Windows Server
2016 and older top out at 1.2.
- Name verification uses the hop's host, or `sni_hostname`. The `Host`
  header names the same server, so a hop dialled by literal with the name
  in `sni_hostname` still reaches a server that routes on `Host` (added
  after v0.9.1, which took `Host` from the address alone).
- Pinning uses `server_fingerprints` with `verify: false`; with `verify`
  on, the pin is checked on top of the chain (`ServerFingerprintVerifier`
  in `src/rustls_config_util.rs` runs webpki first), which a self-signed
  certificate cannot pass. The pin is the SHA-256 of the end-entity
  certificate (`src/rustls_config_util.rs:112-116`), the same value SSTP's
  SHA-256 Cert Hash carries, so a pinned deployment's fingerprint is what
  the server will check binding against.
- [MS-SSTP] §3.2.4.1 wants `id-kp-serverAuth` or `anyExtendedKeyUsage`.
  webpki's server verification differs in both directions
  (`rustls-webpki` 0.103.16, `verify_cert.rs:388-399` and `:531`). It
  requires `serverAuth` when an EKU extension is present, so it refuses a
  certificate that carries only `anyExtendedKeyUsage`. It accepts a
  certificate with no EKU extension. A server whose certificate fails the
  first way is reached by pinning it. The second is a laxity this does not
  add a check for: it is what every other TLS outbound in shoes accepts.
  With pinning instead of verification, the pin is the check.
- The Cert Hash is computed over `peer_certificates()[0]`, the leaf, with
  `aws_lc_rs::digest` (SHA-1 or SHA-256). Both are already in the tree.

## Configuration

```yaml
client_chain:
  - address: "vpn.example.com:443"
    protocol:
      type: sstp
      username: "alice"            # DOMAIN\alice for a Windows domain account
      password: "a strong password"
      # Optional, shown with their defaults:
      auth: [mschapv2]             # also: pap. Listed in order of preference
      mtu: 1280
      tls:
        verify: true
        sni_hostname: "vpn.example.com"   # default: the host in `address`
        server_fingerprints: []           # SHA-256 of the server certificate
```

| Field | Default | Validation |
| --- | --- | --- |
| `username` | required | 1 to 256 ASCII characters, no NUL (RFC 2759 §4: "0 to (theoretically) 256 case-sensitive ASCII characters"; empty is refused because no server accepts it) |
| `password` | required | `Redacted<String>`. At most 256 UTF-16 code units (RFC 2759 §4) |
| `auth` | `[mschapv2]` | Non-empty, no duplicates, from `mschapv2` and `pap`. PAP is never used unless listed |
| `mtu` | 1280 | 576 to 1500. See Performance for the default, for why not more, and for the floor |
| `tls.verify` | `true` | `false` without `server_fingerprints` is refused: "SSTP would send your credentials to any server that answers; pin its certificate with server_fingerprints or leave verify on" |
| `tls.sni_hostname` | the host in `address` | Same handling as the `tls` client's field |
| `tls.server_fingerprints` | none | Same format and parser as the `tls` client's (`process_fingerprints`, `src/rustls_config_util.rs:317`) |

The hop's `bind_interface` and `tcp_settings.no_delay` (default on) apply
to the TCP socket. A `transport` other than TCP, `quic_settings`, and a
`type: tls` wrapping `sstp` are refused, the last with: "SSTP does its own
TLS; put the settings under the sstp protocol's tls block".

The TLS settings sit inside the protocol, not in a hop-level block. That
follows where Hysteria2 keeps its own transport options (`obfs`,
`port_hopping`). The field names are the `tls` client's, so nothing new has
to be learned. Reusing the generic `type: tls` wrapper instead was
considered and declined: it is a per-stream `ProxyConnector`, and making
the chain builder consume one as a terminal connector's configuration
special-cases the composition model for one protocol.

Per the `adding-a-config-option` skill:
- every field goes into CONFIG.md, with three warnings:
  - PAP sends the password in the clear inside TLS;
  - a network change ends every flow;
  - SoftEther expects `HUB\user`;
- `examples/sstp_client.yaml` parses;
- the example joins the `--dry-run` smoke loops in `test.yml` and
  `build.yml`, since parsing needs no certificate.

## Performance

SSTP is TCP inside TCP. Its throughput is set by three things:
- the inner stack's windows;
- how much queue sits between the inner TCP and the wire;
- what each packet costs to frame and encrypt.

This section says what the design does about each. "Measured" means
measured on this implementation, by the method under Testing. Nothing
below is promised as a number before then.

### The data path

Two tasks per session, beside the netstack's own task (one worker per
session, no per-packet spawning; AGENTS.md "Per-packet code"):

```
netstack ──ip_to_tunnel (256, backpressured)──► writer ──TLS──► TCP
netstack ◄─ip_from_tunnel (256, awaited)─────── reader ◄─TLS─── TCP
                           control (16) ──────► writer (polled first)
```

**Writer.**
1. Await one packet, then take everything else already queued with
   `try_recv`. Stop when the batch buffer has no room for another
   maximum-size frame. That is Open-SSTP-Client's
   `OutgoingManager.kt:31-53`.
2. For each packet, write the 8 bytes of SSTP and PPP header and then the
   packet into one reusable buffer. The buffer is allocated once per
   session, at 16 KiB, TLS's largest record plaintext.
3. Issue one `write_all` per batch. Do not flush per packet.

rustls encrypts each `write` call into its own record or records, and never
merges records across calls (`rustls` 0.23.46,
`common_state.rs:352-401`). Batching is therefore the only way a burst
shares a record.
- Record overhead in TLS 1.3 with AES-GCM is 22 bytes: a 5-byte header,
  1 content-type byte and a 16-byte tag. TLS 1.2 adds an 8-byte explicit
  nonce, for 29.
- At 1500-byte packets, one record per packet spends 22 bytes and one
  AEAD call per 1508 bytes.
- A full batch of ten spends 22 bytes and one AEAD call per ~15 KB.
- sstp-client pays the first rate (`sstp-stream.c:649`); Open-SSTP-Client
  pays the second.

**Control messages.** Echo responses, LCP replies and Call Disconnect go
through a separate channel of 16 that the writer polls first, so a bulk
upload cannot hold an echo reply back. A full control channel means the
peer is sending control faster than one TLS write drains it, which only a
broken or hostile peer does. The session ends with an error.

**Reader.**
- **Buffering.** It reads into one fixed buffer of 32 KiB plus 4095 bytes,
  allocated once per session and big enough for a full record plus a
  straddling packet. It parses every complete SSTP packet in place, then
  moves the incomplete tail (at most 4094 bytes) to the front.
- **Control is handled inline.** No copy is made.
- **IP packets.** Each one becomes the one `Vec<u8>` the netstack channel's
  item type requires.
  - That is one allocation per inbound packet, the same as AmneziaWG's
    receive path today, whose channels carry `Vec<u8>` too
    (`src/amneziawg/tunnel.rs:396-399`).
  - Changing the channel to a pooled buffer, which the TUN stack already
    uses (`PooledBuffer`, `src/tun/stack_common.rs:571`), is a change to
    both tunnels. It is recorded as debt rather than done here.
- **Nothing is ever dropped.** When `ip_from_tunnel` is full, the reader
  awaits the send. This is deliberately unlike the UDP tunnels:
  - The outer TCP is flow-controlled. A reader that stops reading closes
    the server's window, which slows the server at no cost.
  - Dropping an inner packet instead would cost an inner retransmission
    that crosses the outer TCP a second time.
  - A full queue here means waiting, and the comment on the channel says
    so.

**Both directions are bounded end to end.**
- The netstack refuses to emit past `ip_to_tunnel`'s free slots, which
  holds 256 packets (`src/buffer_sizing.rs:258-270`).
- The writer holds one batch.
- rustls buffers at most its default 64 KiB of ciphertext.
- The kernel holds the rest.

### TCP inside TCP

The inner TCP is smoltcp's, between the netstack and the destination. The
outer TCP is the kernel's, to the SSTP server. The outer one is reliable,
so the inner one never needs to retransmit, and when it does, the
retransmission is pure waste that travels the same queue as the data it
duplicates. Three choices keep that rare:

1. **No inner loss is manufactured.** Every hop between smoltcp and the
   socket backpressures. Nothing drops (above). Inner TCP then sees loss
   only as a timeout.
2. **The inner RTO is never short.** smoltcp's minimum RTO is 1 s
   (`smoltcp` 0.14.0, `socket/tcp.rs:155`). An outer loss recovered by
   fast retransmit takes about one RTT and never reaches it. What reaches
   it is an outer stall of over a second: a lossy mobile link with outer
   RTO backoff. That case is TCP-inside-TCP's inherent cost, and every SSTP
   client pays it, Windows' included.
3. **The kernel's queue is kept short where the platform allows it.** A
   send buffer of megabytes holds seconds of data at mobile rates. That
   inflates the inner RTT, the inner RTO follows it up, and the inner
   window keeps growing into a queue that is not bandwidth. On Linux and
   Android, `TCP_NOTSENT_LOWAT` (socket2's `set_tcp_notsent_lowat`, unix
   only, behind its `all` feature, `socket2` 0.6.5 `sys/unix.rs:1918`) caps
   the unsent bytes the kernel queues. On macOS and iOS the same option is
   set through `libc::TCP_NOTSENT_LOWAT`. Windows has none.
   - The value starts at 128 KiB, which is enough to keep a 100 Mbit/s,
     10 ms path busy.
   - It is on by default only if the A/B under Testing shows it does not
     cost bulk throughput. If it does, it ships off with the measurement
     written down.

Consequence, stated in CONFIG.md: on a lossy path, SSTP will be slower than
AmneziaWG or Hysteria2 to the same place, and nothing in this design
changes that. It is chosen for reach, not speed.

### The inner windows and MTU

The netstack's socket buffers are AmneziaWG's, sized per platform by
`buffer_sizing` (`default_remote_rx_window_size`, `:203`;
`default_remote_tx_window_size`, `:248`), for the same reason: they are the
inner connection's receive window and send window against a server on the
internet.

**The MTU is 1280 by default, and above 1500 is not offered.**
- 1280 rather than 1500, changed after the first live run. That server
  offered an MRU of 1350, and every packet toward one large site over about
  1280 bytes vanished with no ICMP: its uplink was presumably a tunnel.
  TLS handshakes stalled; 1280 worked and 1300 did not. An OS TCP stack
  would discover the path MTU; smoltcp does none, so the client must not
  rely on one. 1280 is the MTU every IPv6 path must carry. Clearing Don't
  Fragment on what the client sends was tried and did not help, which
  places the loss on packets toward the client, sized by the MSS it
  advertises.
- The device MTU is the smaller of the configured `mtu` and the server's
  MRU, so the client never sends a frame the server would refuse.
- An inner MTU above 1500 would cut per-packet costs only if segments grew
  with it. For TCP they do not: smoltcp sends at most the far host's MSS,
  and a host on an Ethernet path advertises 1460 whatever we offer. UDP
  datagrams above 1500 would leave the SSTP server fragmented.
- SoftEther caps the MRU at 1500 (`Proto_PPP.h:51`) and accel-ppp at 1452
  by default (`sstp.c:180`). A larger proposal would mostly be negotiated
  down anyway.
- The floor of 576 is IPv4's minimum reassembly size.

### What a session costs

| | Per session | Per connection |
| --- | --- | --- |
| Reader buffer | 36 KiB | — |
| Writer batch buffer | 16 KiB | — |
| rustls buffers | up to 64 KiB of unsent ciphertext, plus record buffers | — |
| Netstack sockets | — | the same as AmneziaWG (`buffer_sizing`'s table) |
| Tasks | netstack, reader, writer | none |

The handshake takes about eight round trips before the first proxied byte:
- TCP: 1.
- TLS: 1 for 1.3, 2 for 1.2.
- HTTP: 1.
- Call Connect: 1.
- LCP: 1. Both sides' requests cross.
- MS-CHAPv2: 1.5.
- IPCP: 1 to 2. The address arrives in a Configure-Nak.

Two writes are pipelined:
- Our LCP Configure-Request goes out the moment the Call Connect Ack
  arrives, without waiting for the server's.
- IPCP's first Configure-Request shares a TLS write with Call Connected.

Sending Call Connect Request before the HTTP `200` arrives would save one
more round trip, but [MS-SSTP] does not allow for it and no reference does
it. It is not done. The session is shared by every connection through the
hop, so the handshake is paid once per session, not per connection.

## Security

- **Credentials.**
  - The password is `Redacted<String>` from parse onward, and so are its
    UTF-16LE form, the NT hash, the MPPE keys, the HLAK and the CMK.
    Those are held in `zeroize::Zeroizing` buffers (`zeroize` 1.9.1 is
    already in the tree) and dropped once Call Connected is sent.
  - No log line or error carries the username, the password, a challenge
    or a response. Errors say what failed and the server's code: "SSTP
    authentication failed: the server refused the credentials (MS-CHAPv2
    error 691)".
  - Tests assert `!err.contains(password)` on every authentication failure
    path.
- **Mutual authentication.** MS-CHAPv2's Success is verified before Call
  Connected is sent, in constant time. A mismatch ends the session as
  "the server did not prove it knows the password". Open-SSTP-Client
  compares with `contentEquals` (`MSCHAPV2Client.kt:145`); this does not.
- **PAP.**
  - It is used only when `auth` lists it, and only if the server proposes
    it or accepts our Configure-Nak to it.
  - Its HLAK is zeros, so crypto binding proves nothing about the
    credentials. It still binds the session to the TLS certificate the
    client saw.
  - CONFIG.md says that PAP exposes the password to whoever terminates the
    TLS, and that this is why `verify: false` is refused without a pin.
- **Downgrade.** The client accepts only an auth method it lists. A server
  that Configure-Naks to anything else ends the session with the method's
  name, never with a silent fallback.
- **Detectability.** SSTP is not a circumvention protocol. The HTTP verb is
  unique to it, and rustls's ClientHello is not Windows schannel's. Anyone
  who terminates or fingerprints the TLS can tell it is SSTP. That is what
  SSTP is, and CONFIG.md says it plainly so nobody picks it for
  censorship resistance.

### Keenetic's camouflage mode

KeeneticOS 4.2 (April 2024) added `sstp-server camouflage`, "providing
greater security against remote service scanning"; the router then shows
its address as `https://<host>/?<secret>`, the secret generated by the
router and readable with `show sstp-server`. Nothing documents what it
changes on the wire, and users report third-party clients failing against
it, so it was found by probing the production router of the live run above
with camouflage on (2026-10-31):

| Request | Answer |
| --- | --- |
| `SSTP_DUPLEX_POST /sra_{…}/` (the standard URI) | `404 Not Found`, `Server: Web server` |
| `SSTP_DUPLEX_POST /sra_{…}/?<secret>` | `200 OK` |
| `…/?secret=<secret>`, the secret as a path or path prefix, as a `Cookie` | `404 Not Found` |
| `GET /` | `200 OK`, a web server |

So the secret is the bare query string on the standard URI, which
[MS-SSTP] §3.2.4.1 allows (its own optional variable is `tenantid`), and
to every other request the router is a web server. This is the one server
in the references that closes active probing, the exposure the Security
section records as not fixable from the client; `camouflage_secret`
carries it, validated to RFC 3986's unreserved characters since it rides
the request line, and a 404 is reported with what it means, never with
the secret. The server double answers the same 404 to a request without
its secret.

## Error handling

| Condition | Behaviour |
| --- | --- |
| TCP or TLS fails, or the certificate is refused | Every resolved address is tried for the TCP connection, in order, within the negotiation deadline, as the other outbounds do; then the build fails with rustls's or the socket's error, prefixed "SSTP: connecting to <host:port>". Cooldown starts |
| The server sends LCP or IPCP Terminate-Request | Terminate-Ack with its identifier (RFC 1661 §5.6), flushed by the writer's teardown, then the session ends as dead |
| HTTP status other than 200, or no header end within 8 KiB | "SSTP: the server answered the SSTP request with <status line>". The status line is the server's text, length-capped, control characters stripped |
| Call Connect Nak | "SSTP: the server refused the call (status <id/status>)". [MS-SSTP] §3.2.5.3.3 lets a client retry, and its note <10> says the Windows client retries 3 times. It also says a Nak arrives only when the server does not carry PPP over SSTP, which a retry cannot change, so this does not retry |
| Ack without the Crypto Binding Request, or offering no hash we support | Call Abort, then fail: "SSTP: the server offered no usable crypto binding" |
| LCP or IPCP does not converge within 10 Configure-Requests, or the 60 s handshake deadline passes | Call Abort, fail naming the phase |
| An auth method we did not list is insisted on (EAP, CHAP-MD5, MS-CHAPv1, PAP when not listed) | Call Abort, fail: "SSTP: the server requires <method>, which is not enabled" (or "not supported") |
| MS-CHAPv2 Failure | Fail with the `E=` code and its RFC 2759 §6 name. No retry |
| MS-CHAPv2 authenticator mismatch | Fail as under Security |
| Server Call Abort or Call Disconnect, or LCP Terminate-Request after Opened | Answer as [MS-SSTP] §3.1.1.1 says (Disconnect Ack, or Terminate-Ack). The session is dead; the next connection rebuilds it |
| A malformed packet: bad version, length below 4 or past the buffered data, an unknown control type, an attribute overrunning its message | Call Abort, then close. The session is dead. A Reserved or R field that is not zero is ignored, as the spec says |
| Hello: nothing received for 60 s, Echo sent, nothing for 60 s more | Close without Call Abort (§3.1.2.3). The session is dead |
| Network change | The session is dead and its socket shut, as under Architecture |
| A connection requested while the session is being built | Waits for the build, as on AmneziaWG. One build serves every waiter |
| Engine stop | One write of LCP Terminate-Request plus Call Disconnect, then close on the Disconnect Ack or after 1 s, whichever is first. [MS-SSTP]'s 5 s wait is for an orderly server-side cleanup that closing the TCP connection also triggers. On mobile, stop latency is what the user sees |

## Testing

**Known-answer vectors**, under `tests/data/kat/`, with provenance in its
README:
- `rfc2759/`: §9.2's username, password, challenges, NT-Response and
  authenticator response, extracted from the RFC text by a script, as
  `rfc8448/` is.
- `rfc3079/`: §3.5.3's 128-bit sample, which uses §9.2's inputs. It
  prints `PasswordHashHash`, `MasterKey` and `SendStartKey128`. That last
  one is derived with `IsServer = TRUE` (§3.3), so it is the server's send
  key, which is the client's `MasterReceiveKey`. The client's
  `MasterSendKey` has no RFC vector; sstp-client's pair covers it.
- `sstp/`:
  - the two Compound MAC cases and the MPPE pair from sstp-client's test
    data (`sstp-cmac.c:329-545`, `sstp-chap.c:351-420`);
  - a SHA-256 binding computed by a short Python script from [MS-SSTP]
    §3.2.5.2.3–4 with the standard library's `hmac`, recorded with its
    inputs. It is a third, independent reading, not ours.
- The sstp-client values are published test data, carried with their
  source named. No code comes with them.

**Codec and automaton tests.**
- `packet.rs`, `ppp/frame.rs`: every message round-trips. Lengths at 4,
  4095 and 4096 are tested, and an attribute overrunning its message, a
  wrong version and a nonzero reserved field each have a test.
- `negotiate.rs`: Nak to the server's MRU, Reject of the DNS options,
  Configure-Reject of ACFC/PFC/VJ, a server that insists on EAP,
  retransmission on an injected clock, Protocol-Reject of IPv6CP and of
  CCP.
- `auth.rs`: the RFC 2759 vector, a `DOMAIN\user` name hashed without its
  domain, Failure parsing, authenticator mismatch.

**End to end against a server double in process** (`src/sstp/testing.rs`),
the way `src/quic_outbound/testing.rs` serves Hysteria2 and TUIC.
- **What it runs.** rustls with a generated certificate, the HTTP response,
  Call Connect Ack with a chosen hash bitmask, LCP, the server side of
  MS-CHAPv2 and PAP, and IPCP assigning `10.99.0.2`.
- **It checks crypto binding as accel-ppp does.** It recomputes the
  Compound MAC from the server HLAK `MasterReceiveKey | MasterSendKey`.
- **IP termination.** Packets it decapsulates go into a small smoltcp
  interface at the server's address that echoes TCP and UDP, which makes the
  double a VPN server in miniature. (This was to have been shoes' own TUN
  stack through a channel-backed `StackDevice`; `src/tun/` compiles only for
  the mobile targets and `--features ffi`, so the default test build could
  not run it.)
- **Construction.** The selector is built with
  `create_tcp_client_proxy_selector`, as production builds it.

Cases:
- TCP and UDP echo through the tunnel, both hash protocols, MS-CHAPv2 and
  PAP.
- Many connections sharing one session.
- A server Call Disconnect followed by a rebuild on the next connection.
- A network change ending the session.
- The 60 s hello, on tokio's paused clock.
- Each refusal in the error table.
- **Backpressure:** a reader that stops makes the double's writes block,
  with no inner retransmission counted.
- **Batching:** a burst of N packets arrives in fewer than N TLS records.
  The double counts records.

Every defect test is proven by planting the defect, per AGENTS.md:
- LEN encoded big-endian;
- the domain kept in the challenge hash;
- the authenticator unchecked;
- PAP used when not listed;
- a data frame sent before Call Connected;
- an inbound packet dropped instead of awaited;
- the writer flushing per packet.

**Live interop** (`.agent/skills/live-interop-check/`), before the PR is
called done. Results are recorded in the PR; nothing from those runs enters
the repository.

| Peer | Proves |
| --- | --- |
| SoftEther in a container | Handshake, both auth methods, `HUB\user`, MRU Nak to 1500, its echo cadence, data |
| accel-ppp with `/dev/ppp`, in a privileged container, hash SHA-1 and SHA-256 configured, certificate hash checking on | Crypto binding, both hashes. A `DOMAIN\user` name, to settle the disagreement recorded above |
| Windows Server RRAS, by hand when one is available | The implementation the protocol is defined by. Not a merge gate, because CI cannot run it. The gap is recorded in ROADMAP if it is not run |

**Verified against a real server (2026-10-30).** A production SSTP server
the user supplied (a Keenetic router, as its camouflage mode showed the
next day), with a Let's Encrypt certificate (so `verify` on, no
pin), MS-CHAPv2, and a Call Connect Ack offering SHA-256; behind a
round-robin name, two server addresses served the run. No details of it
enter the repository. What worked:
- the whole handshake, every time: TLS, the HTTP request, call setup, LCP,
  MS-CHAPv2 with the server's proof checked, Call Connected with the
  SHA-256 binding (accepted), IPCP with an address and one DNS server;
- HTTPS to a spread of sites, several connections at once over one
  session, a DNS query over UDP through SOCKS5;
- 100 MB downloads at 3.0 to 5.0 MB/s on the release build, with shoes at
  7% of a core; the path from the test machine to that server, not shoes,
  is the ceiling, though no second SSTP client was run to prove it.

What it found, both fixed before the PR:
- **Names resolved to IPv6 first.** The connector took the resolver's first
  address, an IPv6 one, which an IPv4-only session cannot carry. It now
  takes the first IPv4 address and says so when a name has none
  (`a_name_is_reached_at_its_ipv4_address`).
- **A path-MTU black hole.** The server offered an MRU of 1350; packets
  toward one large site over about 1280 bytes vanished with no ICMP, so
  every TLS handshake to it stalled. 1280 worked, 1300 did not. Clearing
  Don't Fragment on what the client sends was tried and did not help, so
  the loss is on packets toward the client, sized by the MSS it advertises.
  The default `mtu` is now 1280 (see Performance).

Not settled by it: some HTTPS destinations failed at every MTU while plain
HTTP to the same host worked. Size is ruled out; filtering on the server's
side of the world would fit, and a second SSTP client against the same
server is what would tell.

**Performance.** `scripts/bench/tunnels.py` gains an SSTP arm against the
accel-ppp container on loopback, with `NETEM` for delay and loss. The
measurements:
- **Throughput and CPU per GB**, upload and download, with 1 and 8
  connections, against three references:
  - sstp-client with `pppd` against the same server;
  - shoes' own AmneziaWG on the same path;
  - no tunnel.
- **Batching on and off.** Off means one write per packet. This shows what
  the writer buys.
- **`TCP_NOTSENT_LOWAT` on and off**, at `delay 25ms` with no loss and with
  0.5% loss. This is the measurement that decides its default.
- **The TCP-inside-TCP penalty**: the same loss rates against AmneziaWG,
  so CONFIG.md can state it with a number rather than an adjective.

The PR for the data path states these numbers. The acceptance bar is that
shoes is no slower than sstp-client and `pppd` at no loss, because it skips
their per-byte HDLC and per-packet records. If it is slower, the PR says
why before it merges.

## Out of scope

Beyond the table under Scope:
- A server.
- Automatic reconnection that keeps flows alive. A new PPP session may get
  a new address, so it cannot.
- Using the server's DNS servers (from IPCP) as a resolver. They are logged
  at `info` and returned by the handshake, so a later change can route
  names to them. Today names resolve through the configured resolver
  before the tunnel is asked for a connection, as with AmneziaWG
  (`src/amneziawg/connector.rs:327-335`).
- Making the netstack's channels pooled. That is recorded as debt shared
  with AmneziaWG.
- Generalising the connector lifecycle into a trait.

## Order of work

Each step is a PR with its own tests, gate and CHANGELOG entry:

1. **Move the netstack and the network-change registry.** Both moves are
   pure, with AmneziaWG behaviour unchanged and its tests green.
2. **The codecs, `crypto.rs` and `auth.rs`**, with the KAT fixtures. No
   connector yet.
3. **Handshake, session, connector and the server double.** Config,
   CONFIG.md, example, smoke loops. End-to-end tests.
4. **Live interop, the benchmark arm, and the `TCP_NOTSENT_LOWAT`
   decision.** ROADMAP's competition list gains SSTP. Any gap left
   (Windows, IPv6, EAP) goes into Recorded debt with what fixing it
   touches.
