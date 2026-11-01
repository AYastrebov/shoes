# OpenConnect client outbound

Design for dialling OpenConnect servers from shoes: the protocol of Cisco
AnyConnect and of ocserv, as the openconnect client speaks it. Client only,
TLS data path only (CSTP); DTLS is a later step. Like SSTP, it is a layer-3
tunnel, so proxied TCP and UDP cross it through shoes' userspace TCP/IP
stack.

Written 2026-10-31 against `mobile` at `884938d` (v0.9.2), after the plan
in `ROADMAP.md` ("Classic VPN clients: OpenConnect"); built the same day,
and the text below was corrected where building it taught otherwise.

## Sources

Every wire detail below was read from these, not recalled.

| Source | Version read | Licence | Used for |
| --- | --- | --- | --- |
| [openconnect](https://gitlab.com/openconnect/openconnect) | 9.21, `70d1e79` (2026-07-19) | LGPL-2.1 | The client: `auth.c` (the XML form exchange), `cstp.c` (CONNECT, framing, keepalive), `mainloop.c` (DPD timing), `http.c` (common headers) |
| [ocserv](https://gitlab.com/openconnect/ocserv) | `c02eb7f` (2026-10-25) | GPL-2.0 | The server: `src/worker-auth.c` (the forms it serves and parses), `src/worker-vpn.c` (CONNECT reply, frame parsing, camouflage), `src/worker-http.c` (User-Agent classes) |
| [draft-mavrogiannopoulos-openconnect-04](https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-04) | July 2023, expired | IETF draft | The protocol as its server's author wrote it down: the auth documents (§2.2.1–2.2.2), the CONNECT headers (§2.2.5), the CSTP framing and types (§2.3), DPD and keepalive (§2.6), the `config-auth` DTD (Appendix B) |
| [tlslink/sslcon](https://github.com/tlslink/sslcon) | `a2f4692` (2026-05-10) | MIT | A 1,300-line Go client (the engine of AnyLink's desktop client): `auth/auth.go` (the two XML templates), `vpn/tls.go` (the frame loop), `session/session.go` (the CONNECT headers it reads) |
| [xen0bit/veepin](https://github.com/xen0bit/veepin), `internal/anyconnect` | `bcac178` (2026-10-20) | MIT | A 2,900-line Go client with an in-process server double and tests: `client.go`, `xml.go`, `wire.go`, `server.go` |
| [SagerNet/sing-openconnect](https://github.com/SagerNet/sing-openconnect) | `cbd68c4` (2026-09-29) | GPL-3.0 | sing-box's client, read to confirm framing choices (`cstp_packet.go`) |
| [openconnect protocol notes](https://www.infradead.org/openconnect/protocols.html) | as published | — | Orientation |

No code is copied. openconnect, ocserv and sing-openconnect are copyleft
and contribute behaviour; sslcon and veepin are MIT and their structure
may be followed where noted. The Rust crates on crates.io (`anyconnect`,
`openconnect-sys`, `openconnect-core`) bind the openconnect C library, with
its GnuTLS or OpenSSL, and build for x86_64 Linux: not a route for a
rustls library that ships on four mobile and desktop targets.

## Problem

A user whose VPN is an ocserv or AnyConnect server cannot reach it through
shoes. Keenetic routers ship an ocserv-based server beside their SSTP one,
with the same camouflage mode, so the user who asked for SSTP has this too.
The protocol is HTTPS on 443 end to end in its CSTP form.

## Scope

In:

- Username and password authentication through the XML aggregate-auth
  exchange, with an optional group (`group_list`) selection.
- The `webvpn` cookie, kept for the session and reused on reconnect.
- `CONNECT /CSCOSSLC/tunnel`, its request headers, and the reply's address,
  netmask, IPv6 address, DNS, MTU, DPD and keepalive.
- CSTP framing, DPD both ways, keepalive, the server's disconnect and
  terminate, and the client's BYE.
- IPv4 and IPv6 inside the tunnel, when the server assigns them.
- Certificate pinning and `verify`, as for SSTP.
- Keenetic and ocserv camouflage: the secret as the first request's query.

Out (each refused in validation if configured, or simply not offered):

- DTLS and ESP; compression (none is advertised, so none is negotiated).
- Client certificates, multiple-certificate auth, SAML/SSO and OIDC,
  second factors (a form asking for more than username and password),
  CSD/host-scan.
- Split routes: shoes routes by its own rules, so the hop carries what
  shoes sends; the routes are logged.
- The other openconnect protocols (GlobalProtect, Pulse, Fortinet, F5).

## What the references do

### Authentication

openconnect's `cstp_obtain_cookie` (`auth.c:1386-1789`):

1. POST to the configured URL path (`/` by default) with
   `Content-Type: application/xml; charset=utf-8` (the draft §2.2.1 says
   `text/xml`; ocserv reads neither, it looks for `<?xml` in the body,
   `worker-auth.c:1545`) and the body of
   `xmlpost_initial_req` (`auth.c:910-944`):
   `<config-auth client="vpn" type="init" aggregate-auth-version="2">`
   with `<version who="vpn">`, `<device-id>`, `<capabilities>` and
   `<group-access>https://host/path</group-access>`, plus `<group-select>`
   when a group is configured. Common headers (`cstp.c:1280-1308`,
   `http.c:1422-1438`): `Host`, `User-Agent`, `Cookie`, `Accept: */*`,
   `Accept-Encoding: identity`, `X-Transcend-Version: 1`,
   `X-Aggregate-Auth: 1`.
2. The answer is a `config-auth type="auth-request"` document with
   `<auth id="main">`, a `<form method="post" action="/auth">` of
   `<input>` elements, and possibly a `<select name="group_list">`
   (ocserv `worker-auth.c:78-101`, `worker-auth.c:594-700`). An `<opaque>`
   element is echoed back verbatim (`auth.c:661-666`, `auth.c:955-961`).
3. The reply is `type="auth-reply"` with the `<opaque>` copy, each input as
   `<auth><name>value</name></auth>`, and the group as `<group-select>`
   under the root (`auth.c:946-1004`). It goes to the form's `action`
   (`auth.c:1770-1773`).
4. Success is `<auth id="success">` (`auth.c:724-725`) with the cookie in
   `Set-Cookie: webvpn=` (ocserv `worker-auth.c:1484-1487`) or in a
   `<session-token>` element (`auth.c:684-686`). ocserv also sets
   `webvpncontext`, which identifies the auth session across requests
   (`worker-auth.c:519-540`); the client returns every cookie it holds.
   Failure is `401` and the connection closes (`worker-auth.c:2287-2297`);
   a form with an `<error>` element is a refusal with a reason. The draft
   §2.2.2 recommends an `X-Pad` header padding each auth request to a
   multiple of 64 bytes so the credentials' lengths do not show; openconnect
   does not send it, sslcon and veepin do not either; this client does,
   since it costs one header.

ocserv answers a form carrying both username and password in one round:
it reads the username, starts the auth, and on `ERR_AUTH_CONTINUE`
re-processes the same request for the password (`worker-auth.c:2245-2257`).
A server that asks for a further field (`secondary_password`, an OTP)
replies with another form, `<auth id="passwd">` or similar; this client
reports that as a second factor it does not do.

ocserv classifies clients by `User-Agent` (`worker-http.c:468-520`):
`AnyConnect-compatible OpenConnect` selects the full `config-auth`
documents; `Open AnyConnect VPN Agent v3` and older selects a reduced form
this client does not parse. The client sends what openconnect 9.21 sends,
`AnyConnect-compatible OpenConnect VPN Agent v9.21` (`main.c:1866`,
`http.c:1013-1021`).

### Camouflage

ocserv's `check_camouflage_url` (`worker-vpn.c:820-862`) runs on GET and
POST until it passes once on a connection (`worker-vpn.c:1060-1073`): the
URL must carry `?<secret>` first in its query; otherwise the answer is a
404 (or a 401 with a realm). Once the auth reaches the cookie stage the
check passes by itself (`worker-vpn.c:827-831`), and CONNECT is not gated
by the URL at all, only by the cookie (`worker-auth.c:1296-1312`, which
answers 405 when camouflage is on and the cookie fails). So the secret goes
on the first POST of each TLS connection, and only there: on a later
request ocserv would not strip it, and the query would miss every handler
(`worker-vpn.c:1076-1082`). CONNECT never carries it: ocserv compares that
URL whole (`worker-vpn.c:2219-2226`) and gates the tunnel on the cookie,
so a reconnect with the cookie sends no secret at all.

### CONNECT

`start_cstp_connection` (`cstp.c:226-685`) sends:

```
CONNECT /CSCOSSLC/tunnel HTTP/1.1
Host, User-Agent, Cookie: webvpn=<cookie>
X-CSTP-Version: 1
X-CSTP-Hostname: <local name>
X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.
X-CSTP-Base-MTU: <link MTU>
X-CSTP-MTU: <tunnel MTU>
X-CSTP-Address-Type: IPv6,IPv4
X-CSTP-Full-IPv6-Capability: true
```

and, without DTLS, nothing `X-DTLS-*`. The reply is
`HTTP/1.1 200 CONNECTED` (ocserv `worker-vpn.c:2260`) and headers of
which the client reads (`cstp.c:397-643`): `X-CSTP-Address` (IPv4, or
IPv6 when it contains `:`), `X-CSTP-Netmask`, `X-CSTP-Address-IP6`
(prefix form), `X-CSTP-DNS`, `X-CSTP-MTU` (required: no MTU aborts,
`cstp.c:645-650`), `X-CSTP-DPD`, `X-CSTP-Keepalive`, `X-CSTP-Idle-Timeout`,
`X-CSTP-Session-Timeout`, `X-CSTP-Banner`, `X-CSTP-Split-Include`,
`X-CSTP-Split-Exclude`, `X-CSTP-Content-Encoding` (an encoding the client
did not offer is an error), `X-CSTP-Rekey-Method`. `503` carries
`X-Reason` (`cstp.c:362-374`); `401` means the cookie is not accepted
(`cstp.c:379-380`, ocserv `worker-auth.c:1305-1308`). The tunnel's bytes
follow the blank line on the same TLS stream.

ocserv's `X-CSTP-MTU` is its link MTU less the DTLS overheads
(`worker-vpn.c:2724-2728`, `worker.h:219-220`); the client's
`X-CSTP-Base-MTU` is read into its link MTU (`worker-http.c:691`).

### Framing

`cstp.c:46-60`: each frame is

```
'S' 'T' 'F' 0x01 | length (u16 BE, payload only) | type | 0x00 | payload
```

Types (`openconnect-internal.h:1076-1082`): 0 data, 3 DPD request, 4 DPD
response, 5 disconnect (client BYE; payload is a reason byte and text,
`cstp.c:1237-1278`, reason 0xb0 user disconnect, ocserv `vpn.h:131-134`),
7 keepalive, 8 compressed data, 9 server terminate.

**One frame per TLS record.** ocserv reads one record with
`gnutls_record_recv` and requires it to hold exactly one frame: a record
whose length differs from the header's is an error that ends the worker
(`worker-vpn.c:3005-3030`, called from `worker-vpn.c:1836-1843`). The
openconnect client makes the same assumption on read (`cstp.c:975-1003`).
So this client may not batch several frames into one record, as the SSTP
writer does; rustls encrypts each `write` into its own records and never
merges across calls, so one `write` per frame, all under one flush, gives
one record per frame and still one socket write per burst. This client
reads frames as a stream, which accepts any server that splits or joins
records.

### Keepalive and DPD

`keepalive_action` (`mainloop.c:454-492`): with a DPD interval `d` from
`X-CSTP-DPD`, send a DPD request after `d` seconds without receiving, again
after `d/2` if still unanswered, and declare the peer dead after `2d`
without receiving. With a keepalive interval `k` from `X-CSTP-Keepalive`,
send a keepalive after `k` seconds without sending. Any received frame
counts as life (`cstp.c:1004`; ocserv likewise, `worker-vpn.c:3036`). A
DPD request from the server is answered with a DPD response
(`cstp.c:1006-1010`; ocserv echoes the frame with the type changed,
`worker-vpn.c:2865-2878`).

On a dead peer openconnect reconnects with the cookie
(`cstp.c:1154-1174`, `cstp_reconnect`). Rekeying is a reconnect too
(`REKEY_TUNNEL`) or a TLS renegotiation (`REKEY_SSL`), which rustls does
not do; ocserv advertises `ssl` with a far-future time for compatibility
(`worker-vpn.c:2545-2581`), so it is ignored.

## Protocol summary

1. TCP and TLS to the server, verifying or pinning its certificate.
2. POST `/` (or the group path, plus `?secret`) with the init document.
3. Parse the form; reply with username, password, group; POST to the
   action. Repeat at most a few rounds while the server sends a form
   whose inputs are only those three.
4. On success, take the `webvpn` cookie.
5. On the same connection, `CONNECT /CSCOSSLC/tunnel`; parse the reply.
6. Frames both ways; DPD and keepalive on the server's intervals.
7. On death, reconnect with the cookie on a new connection; on 401, run
   the authentication again.

## Architecture

The outbound is a `TerminalConnector`, the only hop in its chain, built
like `src/sstp/`:

| Module | Does |
| --- | --- |
| `src/openconnect/auth.rs` | The XML documents: building init and auth-reply, parsing forms, success, errors, `opaque` |
| `src/openconnect/http.rs` | The small HTTP/1.1 client over the TLS stream: requests, response heads, `Content-Length` and chunked bodies, `Set-Cookie` |
| `src/openconnect/cstp.rs` | The frame codec, and the CONNECT request and reply |
| `src/openconnect/handshake.rs` | TCP, TLS, auth, CONNECT, under one deadline |
| `src/openconnect/session.rs` | The data path and DPD/keepalive |
| `src/openconnect/connector.rs` | The lifecycle: one session per hop, the cookie kept across rebuilds, the cooldown, the network-change listener |
| `src/openconnect/testing.rs` | The in-process server double |

XML parsing is `src/openconnect/xml.rs`, two hundred lines of scanner
producing a tree: the documents are a few hundred bytes of a known shape,
ocserv reads them by substring search, and a parser crate would have been
measured against the mobile size band for the sake of two document shapes.

The netstack (`src/netstack.rs`) is given the IPv4 address with its
netmask and, when assigned, the IPv6 address with its prefix; destinations
of the family the session has are carried, others refused with a message
naming the family, as SSTP does for IPv6.

### Data path

```
netstack ──ip_to_tunnel──► writer ──one TLS record per frame──► TCP
netstack ◄─ip_from_tunnel─ reader ◄─frames parsed as a stream── TCP
            control (16) ─► writer (polled first)
```

The writer drains what is queued, writes each frame with its own `write`
and flushes once. rustls' 64 KiB buffer limit, which truncates a plaintext
write, is lifted on the connection so that the one-frame-per-record rule
does not depend on the TLS stream draining each record before the next
write, which it does today. Inbound, a frame is bounded by the codec's
16 KiB and by the family the link carries, not by the configured MTU:
openconnect accepts oversize frames on purpose (`cstp.c:961-964`). No allocation per packet beyond the netstack's owned
`Vec`; one reusable frame buffer. Nothing drops: the reader waits on a full
inbound channel, as SSTP's does, and the outer TCP paces.

## Configuration

```yaml
protocol:
  type: openconnect
  username: string
  password: string
  group: string?               # sent as group-select
  path: string?                # the URL path to POST first; default "/"
  mtu: 1280                    # default 1280, 576..=1500; also the cap on the server's
  tls:
    verify: true
    sni_hostname: string?
    server_fingerprints: [string]?
  camouflage_secret: string?   # Keenetic / ocserv camouflage
```

Limits, as for SSTP where they mean the same: username and password 1 to
256 characters; camouflage secret RFC 3986 unreserved characters; `verify:
false` only with a pin. `path` must start with `/` and carry no query.
`tcp_settings` applies (the transport is TCP); `transport` is refused.

## Error handling

| Condition | Result |
| --- | --- |
| 404 or 401 with camouflage off | "the server may have camouflage on: set camouflage_secret" |
| 404 with camouflage on | "the camouflage secret may be wrong" |
| 401 to the auth reply, or a form with `<error>` | Authentication failed, with the server's message; never the credentials |
| A password-only form after the password went out | "did not accept the login and asks for a password again", with the server's message: ocserv's shape for both a refused password ("Login failed.", `worker-auth.c:2248-2262` then `558-586`) and a one-time code, told apart only by the text; the password is not sent twice |
| A form asking for anything but username, password and group | "the server asks for a second factor (…), which this client does not do" |
| An SSO form, a certificate request | Named and refused |
| CONNECT 401, or 405 under camouflage | Cookie refused: run the authentication again once, under the same negotiation deadline |
| CONNECT 503 | Refused with the `X-Reason` |
| No `X-CSTP-MTU`, no address | Refused, as openconnect does |
| `X-CSTP-Content-Encoding` | Refused: none was offered |
| A frame with a bad magic or reserved byte | The session ends: the stream is out of sync |
| An unknown frame type | Ignored, as ocserv does |
| Server disconnect or terminate | The session ends; the next connection reconnects with the cookie |
| No frame for 2 × DPD | The session ends |
| Network change | The session ends at once |

## Testing

- Unit: the frame codec both ways and on a split stream; the XML builders
  and parsers against ocserv's own templates (`worker-auth.c:51-106`)
  and openconnect's comment examples (`auth.c:794-812`); the CONNECT reply
  parser on a header block shaped like ocserv's.
- End to end against a server double in `testing.rs` that speaks ocserv's
  half: the init and auth-reply exchange with a cookie, camouflage, the
  CONNECT reply, DPD, and an echoing smoltcp interface behind it, as
  `src/sstp/testing.rs` does. It reads one TLS record at a time from the
  raw TCP stream and fails a session whose record holds other than one
  frame, which is ocserv's rule.
- Tests: TCP and UDP echo; a wrong password says so without the password;
  a second-factor form is named; the cookie is reused after a server
  disconnect without a second authentication; a refused cookie
  re-authenticates; camouflage with, without and with the wrong secret;
  the pin; the selector path from YAML; DPD answered; a dead peer detected.
- A live run against the user's Keenetic and against ocserv, recorded in
  words only. **Run 2026-11-02 against ocserv 1.6.0 on the user's VPS**
  (camouflage on, TLS verified against a public certificate, IPv4-only
  tunnel, DTLS off on the server): `tests/live_socks.rs` passed all four
  checks, and a shell loop around the same config saw the session on the
  server, held it for over three minutes with the server's DPD answered,
  rebuilt it on the next request after `occtl disconnect user`, and saw it
  gone after the client's stop. A 10 MB download ran at the home link's
  ceiling. A destination with only an IPv6 address was refused by name, as
  "Error handling" asks. The Keenetic run is still owed.

## Out of scope

DTLS (the roadmap's second step, if CSTP proves the limit), compression,
client certificates, SSO, second factors, split routes, the other
openconnect protocols.
