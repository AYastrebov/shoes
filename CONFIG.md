# Configuration Reference

shoes uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [Server Protocols](#server-protocols)
- [TUN Config](#tun-config)
- [Client Config](#client-config)
- [Client Protocols](#client-protocols)
- [Rules System](#rules-system)
  - [Rule-sets](#rule-sets)
  - [Protocol sniffing](#protocol-sniffing)
- [Named Groups](#named-groups)
- [Named PEMs](#named-pems)
- [Advanced Features](#advanced-features)
- [Command Line](#command-line)

## Configuration Structure

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- **Server Config** - Defines a proxy server instance
- **TUN Config** - Defines a TUN/VPN device for transparent proxying
- **Client Config Group** - Defines reusable upstream proxy configurations
- **Rule Config Group** - Defines reusable routing rules
- **Named PEM** - Defines reusable certificate/key data

```yaml
# Server configs have 'address' or 'path'
- address: "0.0.0.0:8080"
  protocol: ...

# TUN configs have 'device_name' or 'device_fd'
- device_name: "tun0"
  address: "10.0.0.1"
  ...

# Client config groups have 'client_group'
- client_group: my-upstream
  client_proxy: ...

# Rule config groups have 'rule_group'
- rule_group: my-rules
  rules: ...

# Named PEMs have 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```

## Server Config

```yaml
# Bind to IP address and port
address: "0.0.0.0:8080"        # IPv4
address: "[::]:8080"           # IPv6
address: "0.0.0.0:443-445"     # Port range

# OR bind to multiple addresses and port ranges (`address` is also accepted)
addresses:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"

# OR bind to Unix socket (TCP only)
path: "/tmp/shoes.sock"

# Protocol configuration (required)
protocol: ServerProxyConfig

# Transport layer (default: tcp)
transport: tcp | quic | udp     # udp: the tproxy inbound only

# TCP settings (only when transport: tcp)
tcp_settings:
  no_delay: true               # Default: true

# QUIC settings (required when transport: quic)
quic_settings:
  cert: string                 # TLS certificate (path or named PEM)
  key: string                  # TLS private key (path or named PEM)
  alpn_protocols: [string]     # Optional ALPN protocols
  client_ca_certs: [string]    # Optional client CA certificates
  client_fingerprints: [string] # Optional client certificate fingerprints
  num_endpoints: int           # Optional, 0 = auto (based on thread count).
                               # Always 1 on Windows (no SO_REUSEPORT); a larger
                               # value is reduced and logged.

# Routing rules (default: allow-all-direct)
rules: string | [RuleConfig]
```

## Server Protocols

### HTTP
```yaml
protocol:
  type: http
  username: string?            # Optional authentication
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks                  # Aliases: socks5
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE)
```

### Mixed (HTTP + SOCKS5)
```yaml
protocol:
  type: mixed                  # Aliases: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE for SOCKS5)
```

Auto-detects HTTP or SOCKS5 protocol from the first byte of the connection.

### Shadowsocks
```yaml
protocol:
  type: shadowsocks            # Aliases: ss
  cipher: string               # See supported ciphers below
  password: string

# Supported ciphers:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string               # aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID, or a name (see "User ids" below)
  udp_enabled: true            # Default: true (enables XUDP)
```

**User ids** (VMess and VLESS, server and client): a UUID of any version,
with or without dashes, or a name of 1 to 30 bytes, such as the ids some
panels issue (`TMG_74317ba5f91`). A name stands for its version-5 UUID in the
nil namespace, which is how Xray and sing-box read it, so the same string
works on both ends. 31 bytes, or more than 36, is refused, as Xray refuses it.
TUIC's `uuid` takes only the UUID form.

**Note:** VMess AEAD mode is always enabled. The legacy `force_aead` field is deprecated and non-AEAD mode is no longer supported.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string              # UUID, or a name (see "User ids" under VMess)
  udp_enabled: true            # Default: true (enables XUDP)
  fallback: string?            # Optional fallback destination for failed auth (e.g., "127.0.0.1:80")
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```

### Snell v3
```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
  udp_num_sockets: 1           # Default: 1, sockets per UDP session
```

### TLS Server
```yaml
protocol:
  type: tls

  # Standard TLS targets (by SNI)
  tls_targets:                 # Aliases: sni_targets, targets
    "example.com":
      cert: string             # Certificate (path or named PEM)
      key: string              # Private key (path or named PEM)
      alpn_protocols: [string] # Optional ALPN
      client_ca_certs: [string] # Optional client CA certs
      client_fingerprints: [string] # Optional client cert fingerprints
      vision: false            # Enable Vision (requires VLESS inner protocol)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig] # Optional rule override

  # Default TLS target (for unmatched/no SNI)
  default_tls_target:          # Aliases: default_target
    cert: string
    key: string
    # ... same fields as tls_targets

  # Reality targets (by SNI). The key "" takes a ClientHello that carries
  # no server name, as Xray's serverNames does.
  reality_targets:
    "www.cloudflare.com":
      private_key: string      # X25519 private key (base64url)
      short_ids: [string]      # Valid client IDs (hex, 0-16 chars)
      dest: string             # Fallback destination (e.g., "example.com:443")
      dest_client_chain: ClientChain?  # Optional proxy chain for reaching dest
      max_time_diff: 60000     # Max timestamp diff in ms (default: 60000)
      min_client_version: [1, 8, 0]  # Optional [major, minor, patch]
      max_client_version: [2, 0, 0]  # Optional [major, minor, patch]
      cipher_suites: [string]  # Optional TLS 1.3 cipher suites (see below)
      vision: false            # Enable Vision (requires VLESS inner protocol)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # ShadowTLS v3 targets (by SNI)
  shadowtls_targets:
    "example.com":
      password: string
      handshake:
        # Local handshake (with own certificate):
        cert: string
        key: string
        alpn_protocols: [string]
        client_ca_certs: [string]
        client_fingerprints: [string]
        # OR Remote handshake (proxy to real server):
        address: string        # e.g., "google.com:443"
        client_proxies: [ClientConfig] # Optional proxies for handshake
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # Buffer size for TLS (optional, min 16384)
  tls_buffer_size: int
```

### WebSocket
```yaml
protocol:
  type: websocket              # Aliases: ws
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/ws")
      matching_headers:        # Optional header filters
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      max_early_data: 0        # Non-zero: accept early data in the path
      early_data_header_name: string?  # Accept early data in this header
      override_rules: [RuleConfig]
```

Early data is a client's first bytes, base64url-encoded in the upgrade
request (sing-box's `max_early_data` and `early_data_header_name`). With
`max_early_data` set and no header name, `matching_path` (default `/`) is a
prefix and the rest of the path is the data. With a header name, the data is
read from that header; for `Sec-WebSocket-Protocol`, which Xray uses, the
response echoes the header.

### HTTPUpgrade
```yaml
protocol:
  type: httpupgrade            # Aliases: http-upgrade, http_upgrade
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/download")
      matching_headers:        # Optional header filters, including Host
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]
```

WebSocket's handshake without its framing, compatible with sing-box's
`httpupgrade`. There is no `ping_type`: without frames there is nothing to ping
with. A request carrying `Sec-WebSocket-Key` is refused with `404`, as the
reference does -- a real WebSocket client would misread the unframed bytes that
follow. Anything else that does not match is refused with `404` too.

### Port Forward
```yaml
protocol:
  type: forward                # Aliases: port_forward, portforward
  targets: string | [string]   # Target address(es)
```

### Redirect (transparent TCP, Linux)
```yaml
- address: "0.0.0.0:51272"
  protocol:
    type: redirect             # No fields
```

The target of the kernel's NAT `REDIRECT`. There is nothing to configure
because there is no protocol: the connection arrives as the client sent it, and
shoes reads where it was going from the socket (`SO_ORIGINAL_DST`) and forwards
it there through the listener's `rules`. Add `sniff: true` to give domain rules
a hostname, since the original destination is always an IP address.

- **Linux only**, TCP only, and only as a listener's own protocol. Each of the
  other cases is refused when the config is loaded.
- **shoes installs no firewall rules.** Without a `REDIRECT` rule sending
  traffic to the port, the listener starts and nothing ever arrives. See
  `examples/transparent_proxy.yaml` for a rule.
- **Bind the wildcard when the clients are other hosts.** `REDIRECT` in
  `PREROUTING` rewrites the destination to the address of the interface the
  packet arrived on, not to `127.0.0.1`, so a listener on `127.0.0.1` never sees
  a LAN client and the kernel answers with a reset. `127.0.0.1` is right only
  for this host's own connections redirected from `OUTPUT`.
- **A direct connection to the port is refused**, which is what keeps a wildcard
  bind from being an open proxy. The kernel decides the destination, never the
  client. A connection nobody redirected has no original destination, in one
  of two ways, and shoes closes it in both. With conntrack loaded, which it
  is on any host that has a `REDIRECT` rule, the kernel reports the listener's
  own address, and shoes treats that as none rather than dial itself. Without
  it the kernel reports nothing at all. Either way the log says `connection
  was not redirected`; if it says so for *every* connection, the `REDIRECT`
  rule is not matching and the clients are reaching the port some other way.
- **A link-local IPv6 destination is refused** (`fe80::/10`). Such an address
  means nothing without its interface, and the scope the kernel reports is not
  carried to the outbound dial.
- **Exclude the host's own addresses from the rule** (`! -d` the LAN subnet and
  the WAN address). shoes dials the original destination *from this host*, so a
  LAN client redirected on its way to the router's admin port or SSH arrives
  there as a local connection, past any `INPUT` rule that keeps the LAN out.
  shoes cannot tell such a destination from any other; the rule has to.
- **Exclude shoes' own traffic from the rule** (`-m owner ! --uid-owner`, a
  mark, or the outbound interface). shoes dials the same address the client
  did, and a rule that matches that dial sends it straight back.

### Tproxy (transparent UDP, Linux)
```yaml
- address: "127.0.0.1:51271"
  transport: udp               # Required, and for this inbound only
  protocol:
    type: tproxy
    udp_timeout: 300           # Seconds a UDP session may sit idle. Default: 300
    udp_nat_max: 4096          # UDP sessions, and separately reply sockets,
                               # across all clients. 1 to 1048576. Default: 4096
```

The target of the kernel's `TPROXY`, for UDP: QUIC, DNS, games and calls from
the clients behind a router. Each datagram arrives as the client sent it; shoes
reads where it was going from the socket (`IP_RECVORIGDSTADDR`), routes it
through the listener's `rules` like any other UDP, and sends the replies from
that same address, so the client sees the remote it spoke to and not shoes.
The two fields are sing-box's, with its defaults, so a config that awg-manager
writes for sing-box means the same here. TCP is the [redirect](#redirect-transparent-tcp-linux)
inbound's.

- **Linux only**, `transport: udp` only, and only as a listener's own
  protocol. `transport: udp` with any other protocol is refused when the
  config is loaded.
- **It needs `CAP_NET_RAW`**, for `IP_TRANSPARENT`; the kernel accepts
  `CAP_NET_ADMIN` instead, which grants much more. Root has both; otherwise
  give the binary the narrower one (`setcap cap_net_raw+ep shoes`) rather
  than running as root. Without it the listener fails to start and says so.
  A filesystem mounted `nosuid` ignores file capabilities.
- **Bind loopback; anything else is refused.** A transparent socket on another
  address also receives datagrams delivered to the host the ordinary way, and
  relays them to the address they were already at, which is shoes talking to
  itself without end. `TPROXY`'s `--on-ip` names the listener, so loopback
  costs nothing.
- **shoes installs no firewall rules or routes.** `TPROXY` marks a datagram,
  and a policy route for that mark is what delivers it to a local socket;
  without both, the listener starts and nothing ever arrives:
  ```sh
  ip rule add fwmark 0x1 lookup 100
  ip route add local 0.0.0.0/0 dev lo table 100
  iptables -t mangle -A PREROUTING -i br0 -p udp ! -d 192.168.1.0/24 \
      -m addrtype ! --dst-type LOCAL,BROADCAST,MULTICAST \
      -j TPROXY --on-ip 127.0.0.1 --on-port 51271 --tproxy-mark 0x1/0x1
  ```
  The `! -d` matters as it does for `redirect`: shoes sends from this host, so
  a datagram for the router itself would arrive as a local one. The `addrtype`
  exclusion keeps out what is not a remote's flow: the router's own addresses,
  and broadcast and multicast, where DHCP, mDNS and SSDP live. TPROXY takes a
  datagram before any local service sees it, so without it `dnsmasq` stops
  hearing DHCP. shoes also drops broadcast, multicast and its own address
  itself, but subnet-directed broadcast only the rule can recognise. Do not put
  a UDP `-m socket --transparent` rule ahead of `TPROXY`: it matches shoes'
  reply sockets, which never read, and the client's next datagrams vanish.
- **`src_valid_mark` must be off for the LAN interface**, or clients behind
  it get nothing. With it on, the kernel checks a marked datagram's source
  against the policy route above, finds the `local` default, and drops the
  datagram as a martian: no error, no counter, and the router's own traffic
  still works, so it looks like a firewall problem. `wg-quick` turns it on
  for every interface (`net.ipv4.conf.all.src_valid_mark=1`) when it routes
  by mark. Either turn it off (`all` and the interface), or leave it and set
  `accept_local=1` on the LAN interface, which works unless that interface's
  `rp_filter` is strict (`1`):
  ```sh
  sysctl -w net.ipv4.conf.all.src_valid_mark=0 net.ipv4.conf.br0.src_valid_mark=0
  # or
  sysctl -w net.ipv4.conf.br0.accept_local=1
  ```
  shoes checks these at startup and warns, naming the interfaces at risk.
- **`udp_nat_max` bounds file descriptors**: the sessions of every client
  together, and as many sockets again for replies. Each listener address has
  its own, so a listener on two addresses can hold twice as many. At startup
  shoes raises the soft open-file limit to the hard one, prints the limit, and
  warns if the listeners at their full `udp_nat_max` would not fit. Past the
  limit new sessions are dropped, not refused at startup: some routers ship a
  soft limit of 1024, below the default.
- **A client is a source socket**, not a LAN host: each DNS query from a
  random port and each QUIC connection is one, and lives until it has been
  idle for `udp_timeout`. At `udp_nat_max` clients a new one evicts the client
  heard from least recently, as sing-box does, and one warning says the cap
  was reached. Each client holds its own UDP router, about 21 KB measured on
  x86_64 (an idle router gives its packet buffers back, to a spare pool of
  at most 2 MiB for the whole process), so `udp_nat_max` is a memory setting
  as well as a descriptor one: the default 4096 can reach about 90 MB. On a router with 256 MB or less, set it to what the memory
  allows, 1024 for example. A client is one entry
  in `/connections`; its sessions are routed one destination at a time.
- **A reply is sent from the remote's own address and port**, so it shares
  that port with any service on the router holding its wildcard: `dnsmasq` on
  `0.0.0.0:53`, say, when a client asks `8.8.8.8`. That works with services
  that set `SO_REUSEADDR`, as most do. A service that set neither it nor
  `SO_REUSEPORT` refuses the share, and replies from a remote on that port are
  dropped.
- **`sniff` is refused.** Sniffing reads a TCP stream's first bytes, and this
  listener carries datagrams.
- **`udp_timeout` is between 1 and 86400 seconds.** A client idle for that
  long in both directions is forgotten.

### Hysteria2
```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # Default: true
  obfs:                        # Optional. Both ends must agree.
    type: salamander
    password: string           # At least 4 bytes
```

Obfuscation scrambles every QUIC packet, including the handshake, so a client
that does not use the same type and password cannot reach this server at all.
There is no error for a mismatch — neither side can decode the other, so it
looks exactly like an unreachable server.

### TUIC v5
```yaml
protocol:
  type: tuic                   # Aliases: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # Default: false (enables 0-RTT for lower latency)
  congestion_control: cubic    # Default: cubic. One of 'cubic', 'new_reno', 'bbr'
  udp_timeout: 300             # Default: 300. Seconds a UDP association may sit idle, 1-86400
```

A UDP association ends when the client dissociates or the connection closes,
or after `udp_timeout` seconds without a packet (sing-box's name and default).
The server sends no heartbeats; the client does.

`congestion_control` governs what the server sends, so it is the one that
decides download speed for its clients. See the TUIC client below for when to
choose `bbr`.

### AnyTLS
```yaml
protocol:
  type: anytls
  users:                       # One or more users
    - name: string?            # Optional display name
      password: string         # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding (e.g., ["stop=8", "0=30-30"])
  fallback: string?            # Optional fallback destination for failed auth
```

AnyTLS is a TLS-based multiplexing proxy protocol with traffic obfuscation. Should be used within TLS or Reality.

### NaiveProxy
```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  users:                       # One or more users
    - name: string?            # Optional display name
      username: string         # Basic Auth username
      password: string         # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
  udp_enabled: true            # Default: true (enables UDP over TCP)
  fallback: string?            # Optional path to serve static files for probe resistance
```

NaiveProxy implements HTTP/2 CONNECT with padding for censorship resistance. Should be used within TLS with `alpn_protocols: ["h2"]`.

## TUN Config

TUN (network TUNnel) devices operate at the IP layer (Layer 3), allowing shoes to act as a transparent VPN.

```yaml
# Linux/Windows: Create TUN device by name
device_name: string            # Device name (e.g., "tun0"; the wintun adapter name on Windows)
address: string                # Device IP address (e.g., "10.0.0.1"). IPv4 only on Windows.
netmask: string?               # Netmask (e.g., "255.255.255.0"). Required (IPv4) on Windows.
destination: string?           # Point-to-point peer (Linux only; refused on Windows,
                               # where it would install a default route)

# iOS/Android: Use existing file descriptor
device_fd: int                 # FD from VpnService (Android) or NEPacketTunnelProvider (iOS)
                               # Not supported on Windows: shoes creates the adapter itself

# Common settings
mtu: 1500                      # Default: 9000 (Linux, Android), 4064 (iOS), 1500 elsewhere
tcp_enabled: true              # Default: true
udp_enabled: true              # Default: true
icmp_enabled: true             # Default: true

# TCP stack sizing (see "Memory" below)
tcp_buffer_size: int?          # Bytes per direction per connection.
                               # Default: 32768 (mobile), 65536 (elsewhere)
max_connections: int?          # Concurrent TCP connections before SYNs are dropped.
                               # Default: 256 (mobile), 1024 (elsewhere)
segmentation_offload: bool?    # Linux only: let the kernel pass TCP segments several at a
                               # time instead of one system call per packet.
                               # Default: true. Refused elsewhere and with device_fd,
                               # whose framing its opener chose. A device_fd opened
                               # with IFF_VNET_HDR must use the default 10-byte
                               # header in host byte order.

# Fake IP (optional, off by default)
fake_ip:
  network: string              # IPv4 CIDR, prefix 8-30. Default: "198.18.0.0/16"
  max_entries: int             # Live mapping ceiling. Default: 8192
  bypass_domains: [string]     # Globs that must resolve for real. Default: none
  bypass_defaults: bool        # Local names resolve for real too. Default: true

# DNS for this TUN session (optional; see "DNS" below for the full shape)
dns:
  servers:
    - url: "https://1.1.1.1/dns-query"

# Routing rules
rules: [RuleConfig]
```

### DNS

The `dns:` block chooses the resolver for everything this TUN session
resolves: client-chain hostnames on connect, UDP destinations, and the
WireGuard/AmneziaWG endpoint's re-resolution on tunnel rebuilds. (A
network-change rebind reuses the already-resolved address; a rebuild
resolves again.) Without the block, the system resolver is used, as before.

Two TUN-specific rules:

- **Prefer IP-address URLs** (`https://1.1.1.1/dns-query`). They need no
  resolution before use. A hostname URL without a `bootstrap_url` is
  rejected at validation in TUN configs — resolving it would silently use
  the system resolver, which is the plaintext leak the block exists to
  prevent. The same rule covers the indirect shapes: a `bootstrap_url`
  group that itself resolves through `url: system`, and a `client_chain`
  hop addressed by hostname. (`url: system` directly in the TUN's own
  group stays allowed: it asks for the system resolver explicitly.)
- **Upstream sockets are excluded from the tunnel.** Every DNS upstream
  socket — UDP, TCP, DoT, DoH, DoQ — goes through the same socket-protector
  path as the proxy connection itself, so on Android/iOS a query cannot
  route into the TUN it is resolving for.

Any group with a UDP, TCP, DoT or DoH resolver in it is rebuilt after 10
minutes of use or a minute idle, asking its `bootstrap_url` again, so a
resolver whose server has moved follows it; a group of only `system` has
nothing to rebuild.

### Memory

The stack allocates four buffers of `tcp_buffer_size` when it accepts a
connection — two smoltcp socket buffers and two ring buffers — so the ceiling is
`tcp_buffer_size * 4 * max_connections`: 32 MiB on the mobile defaults, 256 MiB
elsewhere. The logged line `TCP stack: buffer=... max_connections=...` reports it
at startup.

A connection through an AmneziaWG outbound pays again on the far side, where the
tunnel's own virtual stack keeps two ring buffers of the same size plus two
socket buffers. Those two are deliberate and not configurable here: they are the
receive window and in-flight send data of a connection whose far end is across
the internet, and shrinking them to the size of a local buffer measured as a 6x
throughput loss. `tcp_buffer_size` covers the device side only, where there is
no round trip to cover.

They are sized apart, but both are now sized per platform. Each is a ceiling on
throughput in its own direction — `window / RTT`, never auto-tuned. The receive
window governs download: at 256 KiB a 26 ms path measured 47.5 Mbit/s where a
kernel TCP stack over the same tunnel reached 156.7. The send buffer governs
upload the same way, and scaling it lifted a single stream from 56 to 156
Mbit/s at 24 ms. Both are 4 MiB / 1 MiB (receive) and 1 MiB / 512 KiB (send) on
desktop / Android, and both stay at 256 KiB inside an Apple Network Extension —
iOS, and the macOS extension too — which is killed at roughly 50 MB. The receive
window is the one buffer here that goes fully resident rather than staying on
untouched zero pages; the send buffer, like the local ones, is lazy.

Note also that most of these are allocation ceilings rather than resident cost:
the buffers are zero-filled pages, so a connection occupies roughly a third of
what it allocates until it fills them. The receive window is the exception just
named — count it in full.

The mobile defaults are chosen for an iOS `NEPacketTunnelProvider`, which is
killed rather than warned when it crosses roughly 50 MB. Neither buffer spans a
network round trip — both sit between the device and a proxy connection in the
same process — so raising them buys burst tolerance rather than throughput. A
value below two MTUs is raised to two MTUs, since a buffer that cannot hold a
segment plus what arrives behind it stalls rather than slows.

### Fake IP

DNS queries arriving over the TUN are answered from `network` instead of being
resolved, and the address is turned back into the domain when the connection
arrives — so the name is resolved at the far end of the proxy, not on the
device.

Queries are intercepted by destination **port**, not destination address, so an
app that hardcodes a public resolver is caught along with one that follows the
system settings.

| Query type | Behaviour |
|---|---|
| `A` | Answered with an address from `network`, TTL 1 |
| `AAAA` | NODATA (`NOERROR`, no answers), so the client falls back to `A` |
| `HTTPS`/`SVCB`, `SRV`, `TXT`, `MX`, everything else | Forwarded, so it gets a real answer |
| Any type for a `bypass_domains` match, or a local name (below) | Forwarded |
| `A` when every address was used in the last 10 minutes | Forwarded (see below) |

Notes:

- Requires `udp_enabled: true`; DNS arrives over UDP. A query a resolver
  sends over TCP to port 53 instead (a truncated answer, or a resolver set to
  TCP) is answered the same way, message by message, and what is forwarded
  goes to the resolver it addressed over one connection the rules judge.
- `network` must be a range that is not routed for real. The default sits in
  `198.18.0.0/15`, reserved for benchmarking by RFC 2544.
- Past `max_entries` the least recently used mapping is recycled, but only
  one unused for 10 minutes. A query and a connection both count as use, so
  an address an app keeps connecting to is never handed to another domain.
  If every mapping was used more recently than that, the query gets the real
  answer, and the connection that follows misses its domain rule. A warning
  is logged once when this starts; raise `max_entries` if it does.
- A connection to an address inside `network` that stands for no domain (one
  handed out before a restart, or recycled since) is refused: TCP gets a
  reset, UDP is dropped. The app then resolves the name again.
- With `bypass_defaults` on, these resolve for real ahead of
  `bypass_domains`: single-label names (`printer`), names at or under
  `local`, `lan`, `home.arpa`, `internal`, `localhost`, `localdomain` and
  `home`, and the reverse zones `in-addr.arpa` and `ip6.arpa`. Set it to
  `false` only if such names really are served at the far end of the tunnel.
- A bypassed query, built in or listed, is forwarded like any other query:
  along the rules for the resolver address it was sent to. Behind a
  catch-all proxy rule, a query for `nas.lan` sent to the router goes to the
  router's address *from the proxy*, as the connection to `nas.lan` would.
  To reach LAN hosts, route the private ranges direct (as
  `examples/tun_fake_ip.yaml` does); that carries the query to the router
  and the connection after it.
- `bypass_domains` patterns are globs matched case-insensitively, where `*`
  spans dots: `*.local`, `captive.apple.com`, `time.*.apple.com`. Use it for
  anything that must reach a host outside the tunnel — captive-portal probes,
  NTP, STUN, and names the tunnel does not carry.
- Restoration happens before routing rules are evaluated, so hostname rules
  match TUN traffic.

**Platform notes:**
- **Linux**: Requires root or `CAP_NET_ADMIN`. Creates device with specified name/address.
- **Android**: Use `device_fd` from `VpnService.Builder.establish()`. Routes configured via VpnService.
- **iOS**: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`.
- **macOS**: Two shapes are accepted, because the platform has two hosts. A
  Network Extension provider passes `device_fd` from
  `NEPacketTunnelProvider.packetFlow` and configures the interface itself. A
  privileged host — see `shoesd` — has shoes create the device, and then
  `address` and `netmask` are required. `destination` is the point-to-point
  peer: leaving it out is warned about rather than refused, but a `utun`
  without one has no peer address.

  `device_name` must be `utunN` if given, and is best omitted — the kernel then
  returns the next free unit, where choosing one races every other utun user on
  the machine. `shoesd` reports the name it got as `interface`; without it,
  `ifconfig` will say. shoes configures the interface only — routes and DNS
  stay yours, and `examples/tun_macos.yaml` carries the commands.
- **Windows 11**: shoes creates a [wintun](https://www.wintun.net) adapter named
  `device_name`; `address` and `netmask` are required, `device_fd` is refused.
  Requires Administrator and `wintun.dll` next to `shoes.exe` or in `System32`
  (the DLL's signature is verified before it is loaded). shoes configures the
  adapter only — routes and DNS stay yours:

  ```powershell
  # Route a prefix into the tunnel (index from: Get-NetAdapter)
  New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias "shoes0" -NextHop 0.0.0.0
  # Point DNS at it if the tunnel should resolve (pairs well with fake_ip)
  Set-DnsClientServerAddress -InterfaceAlias "shoes0" -ServerAddresses 10.99.0.1
  ```

**Example (Linux):**
```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: "uuid"
```

**Example (Fake IP):** see `examples/tun_fake_ip.yaml`.
**Example (Windows):** see `examples/tun_windows.yaml`.

## Client Config

Used in rules to specify upstream proxies.

`name` is optional and identifies this outbound in `stats::snapshot()`. An
outbound without one is keyed by its address instead, which works but is
neither stable across config edits nor meaningful to show a user. Two
outbounds sharing a name but not an address are rejected at config load.

`direct` is **reserved**: every direct outbound is counted against it, so it
cannot name anything else. Naming a server in one chain but not in another
splits its figures across two rows; shoes warns when it sees that.

```yaml
name: string                   # Optional; identifies this outbound in stats
address: string                # Proxy server address (e.g., "proxy.example.com:1080")
protocol: ClientProxyConfig
transport: tcp | quic          # Default: tcp
bind_interface: string         # Optional, Linux/Android/Fuchsia only

tcp_settings:
  no_delay: true

quic_settings:
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
```

## Client Protocols

### Direct
```yaml
protocol:
  type: direct
```

### HTTP
```yaml
protocol:
  type: http
  username: string?
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks
  username: string?
  password: string?
```

### Shadowsocks
```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

### Snell
```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    padding: false
```

**Note:** VMess AEAD mode is always enabled. The legacy `aead` field is deprecated.

With `aes-128-gcm` or `chacha20-poly1305` the client asks for global padding,
as Xray's client does. `cipher: none` works against sing-box and shoes
servers, but current Xray servers no longer accept it; use an encrypting
cipher there.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    padding: false
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    padding: false
```

### H2MUX Multiplexing

H2MUX speaks sing-box's multiplexing protocol, for VMess, VLESS, and Trojan client protocols. Each proxied connection opens its own h2mux session; there is no session pool, so streams are not yet shared between connections.

```yaml
h2mux:
  padding: false               # Enable padding for traffic obfuscation (default: false)
```

`max_connections`, `min_streams` and `max_streams` are accepted so a config written for sing-box loads, and have no effect: setting one logs a warning.

**Server support:** H2MUX is auto-detected on servers. No configuration needed.

### TLS Client
```yaml
protocol:
  type: tls
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  tls_buffer_size: int
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig
```

`sni_hostname` unset sends the outbound's hostname, if it has one; `null`
or `""` sends no server name at all. A name rustls cannot hold (one with a
space, say) is refused when the config loads. With `verify: true` the
certificate is checked against the name sent, or, when none is sent,
against the address dialled: a hostname, or an IP that the certificate
must carry as an IP SAN.

### Reality Client
```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites (see below)
  client_version: [26, 3, 27]  # Optional [major, minor, patch] (default: 26.3.27, see below)
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality `sni_hostname`:** required, unless REALITY is the outermost layer
and the outbound's `address` is a hostname, which is then used. A missing
one is a config error. `sni_hostname: ""` sends a ClientHello with no server
name, for a server whose names include `""`. An IP address is sent the same
way, since a server name cannot carry one.

**Reality cipher suites:** Valid values are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. If not specified, all three are offered/supported.

**Reality client version:** the version the client reports in its session ID, which the server compares against its `min_client_version` / `max_client_version` (the same `[major, minor, patch]` format; each part is 0-255). The default is Xray-core's latest stable release, 26.3.27 (checked 21 October 2026). Xray v26.7.28 refuses anything below 26.3.27 when its config sets no minimum, and the Amnezia app installs exactly that Xray version, so every XRay server it creates would otherwise refuse the client. A refused client is not told so: the server forwards it to its decoy site, and the connection fails with a certificate error, as if the server were a plain website. Set this only when a server pins a range that excludes the default.

### ShadowTLS Client
```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # Optional SNI override; "" sends no server name
  protocol: ClientProxyConfig
```

### WebSocket Client
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  max_early_data: 0            # Send up to this many bytes of the first write in the request
  early_data_header_name: string?  # Header for early data; unset, it goes in the path
  protocol: ClientProxyConfig
```

With `max_early_data` set, the upgrade request waits for the first write and
carries up to that many of its bytes, as sing-box's client does; the rest
follow as WebSocket frames. The request carries no more than fits one HTTP
line under shoes's 4096-byte limit (about 3000 bytes), so a shoes server
can read it. Match the server's settings: sing-box defaults to
the path, and Xray needs `early_data_header_name: Sec-WebSocket-Protocol`.

The request always carries a `Host` header: a `Host` entry in
`matching_headers` if there is one, otherwise the proxy's address as dialled
(`host:port`), as sing-box sends. Put the CDN or fronted name in
`matching_headers` when it differs from the address.

### HTTPUpgrade Client
```yaml
protocol:
  type: httpupgrade
  host: string?                # Sent as the Host header
  matching_path: string?
  matching_headers:
    header_name: string
  protocol: ClientProxyConfig
```

The request always carries a `Host` header, since a Go server answers one
without it with `400`. It is `host` if set, otherwise the TLS server name of the
layer below, otherwise the proxy's address as dialled (`host:port`) -- sing-box's
order. Set `host` whenever a CDN, or a sing-box server with its own `host`
configured, sits in front. `Host`, `Connection` and `Upgrade` in
`matching_headers` are ignored -- the transport owns all three.

### Port Forward (No-op)
```yaml
protocol:
  type: portforward            # Aliases: noop
```

Passes through the raw connection without protocol wrapping. Useful for testing or transparent proxying.

### AnyTLS Client
```yaml
protocol:
  type: anytls
  password: string             # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding scheme
  min_idle_session: 0          # Idle sessions kept past the 30 s idle timeout
```

Sessions are reused the way the reference client reuses them: a connection
takes the most recently idle session instead of opening a new TLS connection,
and a session goes back to the pool when its connection ends. Sessions idle for
30 seconds are closed, except for the `min_idle_session` most recent. A padding
scheme the server sends (`UpdatePaddingScheme`) replaces the configured one for
every later session.

### NaiveProxy Client
```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  username: string             # Basic Auth username
  password: string             # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
```

### Hysteria2 Client
```yaml
protocol:
  type: hysteria2              # Aliases: hy2
  password: string
  udp_enabled: true            # Default: true
  obfs:                        # Optional. Both ends must agree.
    type: salamander
    password: string           # At least 4 bytes
  port_hopping:                # Optional. See below.
    ports: "20000-50000"
    interval_ms: 30000
```

The password is one opaque string. A server that authenticates by username and
password expects them joined: `"<username>:<password>"`.

A mismatched `obfs` password produces no error. Neither side can decode the
other's packets, so the connection simply never establishes and looks exactly
like an unreachable server. Check it first when a Hysteria2 outbound times out.

#### Port hopping

A Hysteria2 server is often published as a port range. `port_hopping` rotates
the client's UDP port across that range on a timer, which is also what keeps
the connection from holding one 4-tuple for its whole life.

```yaml
- address: 203.0.113.10:443
  protocol:
    type: hysteria2
    password: ...
    port_hopping:
      ports: "20000-50000"       # or "1234,5000-6000,7044"
      interval_ms: 30000         # default 30000, minimum 5000
      # or, instead of interval_ms:
      # min_interval_ms: 15000
      # max_interval_ms: 45000
```

**`ports` replaces the port in `address`.** In the example above, 443 is never
dialled. This matches the reference client, and it is what a `hysteria2://`
link's multi-port parameter means.

`address` must be a literal IP when port hopping is on. The peer address is
fixed for the connection's life - that is what stops QUIC from seeing a path
change on every hop - so a hostname has nowhere to re-resolve to, and the
combination is refused at config load.

Both the local and the destination port move on each hop. Rotating only the
destination would leave the flow linkable by its unchanged source port, which
is the thing port hopping exists to prevent.

### TUIC Client
```yaml
protocol:
  type: tuic                   # Aliases: tuic_v5, tuicv5
  uuid: string                 # UUID
  password: string
  udp_enabled: true            # Default: true
  udp_relay_mode: native       # Default: native. Either 'native' or 'quic'.
  heartbeat_ms: 10000          # Default: 10000
  congestion_control: cubic    # Default: cubic. One of 'cubic', 'new_reno', 'bbr'
```

The heartbeat is one per connection, sent while any TCP stream or UDP
association is open on it, as the reference client sends it.

`congestion_control` is the controller for what this end sends, so on a client
it governs upload, and the server's own setting governs download. The two ends
do not negotiate it and need not match. `cubic` is the default, as in the TUIC
reference and sing-box, and it collapses on a lossy path: at 50 ms with 0.5%
loss a single stream carried 5 to 11 Mbit/s on Cubic and about 500 on `bbr`.
Choose `bbr` at both ends for a lossy or long-distance path. On a clean path
between different implementations it can be somewhat slower than Cubic.
`newreno` is accepted as another spelling of `new_reno`.

`udp_relay_mode: native` carries UDP over QUIC datagrams, and `quic` carries
them over unidirectional streams. Datagrams are cheaper; streams are the way
through a path that drops or mangles QUIC datagrams, and they carry a packet
larger than the datagram limit without fragmenting it. The server replies in
whichever mode the association's first packet used.

`zero_rtt_handshake` is a server-side option only. The client rejects it rather
than accepting it and performing an ordinary handshake.

### SSTP Client
```yaml
protocol:
  type: sstp
  username: string             # DOMAIN\user for a Windows domain account
  password: string
  auth: [mschapv2]             # Default: [mschapv2]. Also 'pap'; in order of preference
  mtu: 1280                    # Default: 1280. Between 576 and 1500
  tls:                         # Optional
    verify: true               # Default: true
    sni_hostname: string?      # Default: the host in `address`; "" sends none. Also the Host header
    server_fingerprints: [string]?  # SHA-256 of the server certificate
  camouflage_secret: string?   # Keenetic's camouflage mode: the part after '?'
```

A client for Microsoft's Secure Socket Tunneling Protocol: PPP over HTTPS,
as Windows RRAS, MikroTik, SoftEther, accel-ppp and some home routers serve
it. Like WireGuard it is a layer-3 tunnel, so it must be the only hop in its
chain; TCP and UDP to any destination go through it. One session, opened on
the first connection, carries every connection through the hop. Design:
`docs/specs/2026-10-30-sstp-client-outbound.md`.

The server's certificate is checked as for the `tls` client, and its hash is
what crypto binding sends. The request's `Host` header names the same server
the certificate is checked against: `sni_hostname` when set, else the host in
`address`. A client that resolves the name itself and dials the literal keeps
the name in `sni_hostname`, and a server that routes on `Host` still finds
its site. With `verify` on, a pin in `server_fingerprints`
is checked on top of the chain, so an SSTP server with a self-signed
certificate (a Windows RRAS box, a router without a public name) is reached
with `verify: false` and its SHA-256 fingerprint in `server_fingerprints`
together. `verify: false` without a pin is refused: the credentials would go
to any server that answered.

`auth` lists the methods the client will use. MS-CHAPv2 is the default, and
it proves the server knows the password as well as the client; the server's
proof is checked. PAP sends the password in the clear inside TLS, to
whoever terminates it, and is used only when listed. EAP, MS-CHAPv1 and
CHAP-MD5 are not implemented; a server that insists on one fails with its
name. SoftEther proposes EAP first and moves to MS-CHAPv2 when refused, and
it reads a `HUB\user` username as the virtual hub to log into.

`mtu` is the largest IP packet either side sends; the server can lower it
further. The default is 1280, IPv6's minimum, rather than the 1500 most
servers offer: a server whose uplink is itself a tunnel can offer more than
its far side carries, and shoes' userspace TCP does no path MTU discovery to
find out, so oversized packets vanish and connections stall mid-handshake.
Raise it only for a server known to carry more.

`camouflage_secret` is for a Keenetic router with its SSTP server's
"Camouflage mode" on (KeeneticOS 4.2 and later). Such a server answers the
SSTP request only when it carries the secret, and is a plain web server to
anything else, so a scanner cannot tell SSTP is there. The router shows the
address as `https://<host>/?<secret>`; put the host in `address` and the
part after `?` here. Without it, or with the wrong one, the connection fails
with a 404 and the error says so. Only Keenetic is known to do this.

`tcp_settings.no_delay` (default on) and `bind_interface` apply to the TCP
connection; `transport` is refused.

Things to know before relying on it:

- **A network change ends every connection through the tunnel.** A TCP
  connection does not survive its interface going away, and a new session
  may be given a different address, so the session ends at once and the
  next connection opens a new one. AmneziaWG keeps its connections; SSTP
  cannot.
- **It is TCP inside TCP.** On a lossy path, a loss on the outer connection
  stalls everything inside it, and SSTP is slower there than AmneziaWG or
  Hysteria2 to the same place. It is chosen for reach: HTTPS on 443 crosses
  networks that block WireGuard's UDP.
- **It is not camouflage on the wire.** Whoever terminates the TLS can tell
  it is SSTP, and shoes' TLS handshake is not Windows'. A Keenetic with
  `camouflage_secret` hides the server from probes, nothing more. Do not
  choose it for censorship resistance.
- **IPv4 only.** The server's IPv6 negotiation is refused, and IPv6
  destinations are unreachable through it.
- Names resolve through the configured resolver before the tunnel is asked
  for a connection; the DNS servers the server offers are logged at `info`
  but not used.

### mieru Client
```yaml
protocol:
  type: mieru
  username: string             # Part of the key derivation, not just a label
  password: string
```

A client for the [mieru](https://github.com/enfein/mieru) protocol, over
mieru's TCP transport. Both fields must match the server exactly: the
encryption key is derived from the password, the username, and the current
time rounded to two minutes.

That last part is worth knowing before debugging a failure. A client and
server whose clocks differ by more than about four minutes cannot agree on a
key, and a device that has not synchronised its clock cannot connect at all.
The error says so rather than reporting a generic authentication failure.

UDP destinations work: mieru carries socks5 UDP-associate inside the same TCP
session, so no separate transport is involved.

Not implemented, and refused rather than ignored if configured: mieru's UDP
transport, session multiplexing, the low entropy encoding, port ranges and the
0-RTT handshake mode. `transport` must be `tcp` — mieru defines exactly two
transports and carrying its TCP framing over QUIC produces bytes no mieru
server understands.

### OpenConnect Client
```yaml
protocol:
  type: openconnect             # Also 'anyconnect', 'ocserv'
  username: string
  password: string
  group: string?               # The group to select when the server offers a choice
  path: "/"                    # Default: "/". Where the login is posted
  mtu: 1280                    # Default: 1280. Between 576 and 1500
  tls:                         # Optional; the same block as SSTP's
    verify: true               # Default: true
    sni_hostname: string?      # Default: the host in `address`; "" sends none. Also the Host header
    server_fingerprints: [string]?  # SHA-256 of the server certificate
  camouflage_secret: string?   # ocserv's and Keenetic's camouflage: the part after '?'
```

A client for the protocol of Cisco AnyConnect and of ocserv, as the
openconnect client speaks it, over TLS only (CSTP): the username and
password exchange, then `CONNECT /CSCOSSLC/tunnel` on the same connection
and IP packets in CSTP frames on it. Like WireGuard it is a layer-3 tunnel,
so it must be the only hop in its chain; TCP and UDP to any destination go
through it, IPv6 too when the server assigns an IPv6 address. One session,
opened on the first connection, carries every connection through the hop.
Design: `docs/specs/2026-10-31-openconnect-client-outbound.md`.

The session cookie the login earns is kept: a tunnel that dropped (a
network change, a server disconnect) comes back with `CONNECT` alone, and
a cookie the server no longer accepts is followed by one fresh login.
Dead peer detection and keepalives run on the intervals the server names.

`group` is sent as the selection when the server's form offers groups;
unset picks the server's first. A group the server does not offer fails
with the list. `path` is where the login is posted, `/` for every server
known; ocserv's `select-group-by-url` reads another path as a group.

Not implemented, and refused by name when a server asks: a second
password or one-time code, a client certificate, single sign-on, the
server's CSD host scan, compression, and the DTLS data path (the tunnel
stays on TLS; a server that offers DTLS is still reached). Split routes
the server sends are logged and not applied: shoes routes by its own
rules, and the hop carries whatever they send it.

The certificate, `sni_hostname`, the `Host` header, `mtu`,
`camouflage_secret`, `tcp_settings` and `bind_interface` behave as for
SSTP above. The camouflage secret goes on the first request of each TLS
connection, where ocserv checks it.

### WireGuard Client
```yaml
protocol:
  type: wireguard
  private_key: string          # This peer's key, base64
  peer_public_key: string      # The server's key, base64
  preshared_key: string?       # Optional, base64
  local_addresses: [string]    # This peer's tunnel addresses, with prefix length
  allowed_ips: [string]        # What goes into the tunnel
  persistent_keepalive: int?   # Seconds; unset sends none
  mtu: 1280                    # Default: 1280
```

A user-space WireGuard tunnel (via awgtun). It owns its transport, so it
must be the only hop in its chain, and `transport` is rejected. The
endpoint's hostname is resolved by the TUN's `dns:` group when there is
one, and again whenever the tunnel is rebuilt.

### AmneziaWG Client
```yaml
protocol:
  type: amneziawg
  # The WireGuard fields above, and:
  awg:
    jc: int                    # Junk packets before the handshake, 0-128
    jmin: int                  # Junk packet size range, bytes
    jmax: int                  #   jmax at most mtu + s4 + 32
    s1: int                    # Random padding before each message type, bytes
    s2: int                    #   0-65535 each
    s3: int
    s4: int
    h1: string?                # Message types replacing WireGuard's 1-4:
    h2: string?                #   a number or an inclusive range ("1000-1999");
    h3: string?                #   omit all four for the standard types
    h4: string?
    i1: string?                # Signature packets (CPS strings), i1-i5
    # 3.0, each optional; setting any runs the tunnel as 3.0
    header_protection_key: string?   # base64 or 64 hex; needs s1-s4 >= 12
    content_padding_addition: string?  # bytes, number or range
    rekey_after_time: string?        # seconds, number or range
    rekey_timeout: string?
    reject_after_time: string?
    keepalive_timeout: string?
    max_handshake_attempts: string?  # a count
    persistent_keepalive_interval: string?
    # 3.1
    random_trailers: false     # Must match the server
    disable_cookies: false     # Local to this peer
```

Every value that shapes the wire format (`h1`-`h4`, `s1`-`s4`, the junk
parameters, the header protection key, the content padding,
`random_trailers`) must match the server exactly; a mismatch is not
reported, the handshake simply never completes. `jc` over 128 (the kernel
module's limit) and `jmax` larger than the tunnel's own datagrams are
refused when the config loads; `s1`-`s4` are 16-bit, as the reference
parses them. A full-size packet reaches the wire at `mtu + s4 + 60` bytes,
so keep `mtu <= 1440 - s4` on a 1500-byte path (shoes warns when it is not).
README.md walks through the 2.0, 3.0 and 3.1 generations with examples, and
`examples/amneziawg_client.yaml` has one of each.

### QUIC-native outbounds

Hysteria2 and TUIC own their transport rather than running over one, which
changes three things about how they are configured:

- **They must be the only hop in a chain.** QUIC needs a UDP socket, and there
  is no way to raise one over another proxy's TCP stream.
- **`transport` and `tcp_settings` are rejected.** The transport is QUIC and is
  not chosen.
- **`quic_settings` is where the TLS options go** — `verify`,
  `server_fingerprints`, `sni_hostname`, `alpn_protocols`, `key` and `cert` all
  mean the same thing here as they do for a QUIC transport. Unlike WireGuard
  and AmneziaWG, these protocols accept the block without a `transport: quic`
  line, because their transport is implied by the protocol.

```yaml
client_chain:
  - address: "example.com:443"
    protocol:
      type: hysteria2
      password: "a strong password"
    quic_settings:
      sni_hostname: "example.com"
      verify: true
```

Congestion control is not configurable. Hysteria2 runs BBR at both ends, which
is what upstream falls back to whenever Brutal is not negotiated; TUIC runs
Cubic, its reference's default.

Not implemented on the client side, and rejected rather than ignored where a
configuration can ask for them: Brutal congestion control and bandwidth
negotiation, `gecko` obfuscation, port hopping, and TUIC's `zero_rtt_handshake`.
See [ROADMAP.md](./ROADMAP.md) for what each costs.

## Rules System

Rules determine how incoming connections are routed.

### Rule Config
```yaml
rules:
  - masks: string | [string]   # IP/CIDR or hostname masks
    action: allow | block
    # For action: allow
    override_address: string?  # Optional address override
    client_chain: ClientChain | [ClientChain]  # Proxy chain(s) for routing
```

### Client Chains

Client chains define how traffic is routed through upstream proxies. Each chain is a sequence of "hops" - proxies that traffic passes through in order.

```yaml
# Single proxy (simplest form)
client_chain: my-proxy-group           # Reference a named group
client_chain:                          # Or inline config
  address: "proxy.example.com:1080"
  protocol:
    type: socks

# Multi-hop chain (traffic goes: client -> hop1 -> hop2 -> target)
client_chain:
  chain:
    - first-proxy-group
    - second-proxy-group

# Multiple chains (round-robin selection)
client_chains:
  - us-proxy-group                     # Chain 1: single hop
  - chain: [proxy1, proxy2]            # Chain 2: multi-hop

# Load balancing at a hop (pool)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # Round-robin between pool members
    - final-proxy
```

**Migration note:** The `client_proxy` / `client_proxies` fields still work but are deprecated. Please migrate to `client_chain` / `client_chains`.

### Mask Syntax
```yaml
# IP/CIDR masks
masks: "0.0.0.0/0"             # All IPv4
masks: "::/0"                  # All IPv6
masks: "192.168.0.0/16"        # Subnet
masks: "10.0.0.1:80"           # Specific IP and port

# Hostname masks
masks: "*.google.com"          # Wildcard subdomain
masks: "example.com"           # Exact match

# Multiple masks
masks:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "*.internal.com"
```

### Built-in Rule Groups
- `allow-all-direct` - Allow all connections, direct routing
- `block-all` - Block all connections

### Rule-sets

A rule-set is a compiled list of domains or IP ranges in sing-box's `.srs`
format. Declare it once at the top level and reference it by name:

```yaml
- rule_set: geosite-ru
  path: /etc/shoes/geosite-ru.srs

- rule_set: geoip-ru
  path: /etc/shoes/geoip-ru.srs
```

Relative paths resolve against the directory of the config file that declared
them, so a config directory can be moved intact.

Reference rule-sets from a rule with `rule_sets`. A rule matches if **any** of
its masks matches **or** any of its rule-sets does, so `masks` may be omitted
when a rule matches purely through a rule-set:

```yaml
rules:
  - rule_sets: [geosite-ru, geoip-ru]
    action: allow
    client_chain:
      protocol:
        type: direct

  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy
```

Compiled lists are published at
[SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite) and
[SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), on their
`rule-set` branches:

```bash
curl -O https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs
curl -O https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs
```

**Supported matchers:** `domain`, `domain_suffix`, `domain_keyword`,
`domain_regex` and `ip_cidr`. Anything else a `.srs` file can carry --
`process_name`, `package_name`, port matchers, the network and Wi-Fi families,
AdGuard matchers, `source_ip_cidr`, and `type: logical` rules -- is refused at
startup with a message naming the field. A rule-set that loads is one that
matches exactly what it says.

Files are read and checked while the config is validated, so `--dry-run` catches
a bad path or a corrupt file. Editing a `.srs` triggers the same reload a config
edit does.

Domain matching lowercases the destination and ignores a trailing dot. `ip_cidr`
is compared against a resolved address only when the server resolves rule
hostnames; otherwise a hostname destination is matched on its name alone.

### Protocol sniffing

A domain rule needs a domain. When a client hands over a bare address -- an app
with its own DoH resolver, one that dials a literal IP, or a client configured
for `socks5` rather than `socks5h` -- every domain rule and every rule-set
silently stops matching.

Sniffing recovers the name from the first bytes of the connection: the
`server_name` extension of a TLS ClientHello, or the request line and `Host`
header of an HTTP/1.x request. It is off by default and enabled per listener,
on a server or on the TUN.

```yaml
- address: 0.0.0.0:1080
  protocol:
    type: socks
  sniff: true
```

The long form spells out the defaults:

```yaml
  sniff:
    enabled: true
    protocols: [tls, http]
    timeout_ms: 300
```

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` inside a `sniff:` block | Whether to sniff at all |
| `protocols` | `[tls, http]` | Which sniffers to run. A single name may be written without a list. An empty list with `enabled: true` is a config error |
| `timeout_ms` | `300` | How long to wait for the client's first bytes |

`timeout_ms: 0` is valid and means "sniff whatever has already been buffered and
wait for nothing". Use it when no added latency is acceptable.

The recovered name is used **for routing only**. A direct connection still
dials the original address and performs no DNS lookup; a connection routed
through a proxy sends the name upstream, so the exit node resolves it -- which
is what a client using `socks5h` is asking for. CIDR masks keep matching the
real address either way.

Some connections are never sniffed:

- a destination that is already a hostname, because there is nothing to
  recover;
- ports 25, 465, 587, 143, 993, 110 and 995 -- SMTP, IMAP and POP3, where the
  server speaks first, so waiting would stall the connection for the whole
  timeout and learn nothing.

Sniffing can never itself fail a connection. If nothing is recognised, if the
protocol carries no name, or if the client says nothing before the deadline,
the connection is routed by address exactly as it would have been. Successful
sniffs are logged at `debug`.

One consequence worth stating plainly: with `sniff` enabled the proxy reads the
first bytes of application payload before deciding where to route it. Those
bytes are not stored, are not logged above `debug`, live only in a
per-connection buffer capped at 16 KiB, and reach the remote unchanged. This is
why the feature is off unless you turn it on.

Note also that with sniffing enabled, protocols that send a success response --
SOCKS5 and HTTP `CONNECT` -- send it **before** the upstream connection is
attempted, because the client will not send anything to sniff until it has one.
A client therefore sees the connection open and then close, rather than an
error code, when the upstream is unreachable.

### Example Rules
```yaml
rules:
  # Direct connection for local networks
  - masks: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    action: allow
    client_chain:
      protocol:
        type: direct

  # Block specific domains
  - masks: ["*.ads.example.com", "tracking.example.com"]
    action: block

  # Route through upstream proxy
  - masks: "0.0.0.0/0"
    action: allow
    client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
```

## Named Groups

### Client Proxy Group
```yaml
- client_group: my-upstream
  client_proxies:              # Define proxies in this group
    - name: proxy-1            # Optional; the key its traffic is counted against
      address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - name: proxy-2
      address: "proxy2.example.com:1080"
      protocol:
        type: socks

# Reference in rules
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream  # Reference by name
```

### Rule Group
```yaml
- rule_group: standard-rules
  rules:
    - masks: ["192.168.0.0/16"]
      action: allow
      client_chain:
        protocol:
          type: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream

# Reference in server config
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules: standard-rules        # Reference by name
```

## Named PEMs

Define certificates once and reference throughout configuration.

```yaml
# From file
- pem: my-cert
  path: /path/to/certificate.pem

# Inline data
- pem: my-key
  data: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

# Reference in config
- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      "example.com":
        cert: my-cert          # Reference by name
        key: my-key
        protocol:
          type: http
```

## Advanced Features

### Vision (XTLS-Vision)

Vision optimizes TLS-in-TLS scenarios by detecting inner TLS traffic and switching to direct mode for zero-copy performance.

**Requirements:**
- Inner protocol MUST be VLESS
- Works with both TLS and Reality

```yaml
# TLS + Vision
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      vision: true
      alpn_protocols: ["http/1.1"]
      protocol:
        type: vless
        user_id: "uuid"

# Reality + Vision
protocol:
  type: tls
  reality_targets:
    "www.google.com":
      private_key: "..."
      short_ids: ["..."]
      dest: "www.google.com:443"
      vision: true
      protocol:
        type: vless
        user_id: "uuid"
```

### XUDP Multiplexing

Automatically enabled for VMess and VLESS when `udp_enabled: true`. Multiplexes UDP traffic over a single connection.

### Proxy Chaining

**Protocol nesting** (wrap one protocol in another):

```yaml
client_chain:
  address: "proxy.example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
```

**Multi-hop chains** (route through multiple proxies sequentially):

```yaml
client_chain:
  chain:
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:443"
      protocol:
        type: tls
        protocol:
          type: vless
          user_id: "uuid"
```

### Hot Reloading

Configuration changes are automatically detected and applied without restarting, after a three-second debounce. A file saved with the same bytes it already had restarts nothing, since a restart drops live connections. Disable with `--no-reload` flag. Sending `SIGHUP` reloads immediately, with or without the watcher, and always reloads, even when no file changed.

### mTLS (Mutual TLS)

Require client certificates for authentication:

```yaml
# Server side
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: server.crt
      key: server.key
      client_ca_certs: [ca.crt]  # Required CA
      client_fingerprints: ["sha256:..."]  # Optional specific certs
      protocol: ...

# Client side
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    cert: client.crt
    key: client.key
    protocol: ...
```

## Command Line

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    Worker threads (default: CPU count)
  -l, --log-file PATH  Log to file (repeatable; "-" means stderr; default: stderr)
  -d, --dry-run        Parse config and exit
  --no-reload          Disable hot-reloading
  -V, --version        Print version and exit

COMMANDS:
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
  generate-vless-user-id                         Generate a random VLESS/VMESS user ID
  check <config.yaml> [config.yaml...]           Parse config and exit (same as --dry-run)
  version                                        Print version and exit
```

`check` exits 0 when every config loads and 1 with the error on stderr
otherwise. A running process reloads on `SIGHUP` immediately, even with
`--no-reload`, which disables only the file watcher.

## Tips

### Generate Keys

**Reality keypair:**
```bash
shoes generate-reality-keypair
```

**Shadowsocks 2022 password:**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID:**
```bash
uuidgen
```

**TLS certificate fingerprint:**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### Security Best Practices

- Use strong, random passwords
- Keep private keys secure
- Use `127.0.0.1` instead of `0.0.0.0` for local-only access
- Use firewall rules to restrict access
- Enable client certificate authentication for sensitive services
- Use Vision with Reality for maximum privacy

### Performance Tips

- Enable `vision: true` for TLS-in-TLS scenarios
- Use `tcp_settings.no_delay: true` for low latency
- Set `quic_settings.num_endpoints` to match worker threads (Linux/macOS; Windows always uses 1)
- Use QUIC transport for high-latency or lossy networks

### Common Issues

- **"Address already in use"**: Change port or stop conflicting service
- **"Permission denied"**: Ports < 1024 require root/admin
- **Reality connection fails**: Verify keys match, UUID matches, SNI matches server's reality_targets key
- **Vision not working**: Ensure inner protocol is VLESS
- **Config validation fails**: Run with `--dry-run` for detailed errors
