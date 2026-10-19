# Session reuse without dialling

Plan PR 3.5 (`docs/plans/2026-10-15-quality-and-correctness.md`); audit NA-N1,
AT-A1/A2. Written 2026-10-19. This is the one architectural change of Phase 3:
for both protocols, the chain has to be able to *not* dial.

## The problem

A chain connects by dialling a TCP connection and running each hop's
`setup_tcp_stream` on it. NaiveProxy and AnyTLS multiplex many proxied
connections over one session, a TLS connection carrying HTTP/2 or AnyTLS
framing. In shoes that session belongs to the innermost handler of its hop,
the one that speaks the protocol. So by the time that handler can say "I
already have a session", the chain has already dialled and the TLS layer has
already handshaken:

- **NaiveProxy (NA-N1):** the handler reused its session and dropped the fresh
  TLS connection unused, so every proxied connection cost one empty TLS
  handshake, a pattern of its own. Its `is_ready` was hard-coded `true` and the
  slot was never cleared, so after one dropped connection every request went
  to a dead session until the process restarted.
- **AnyTLS (AT-A1/A2):** there is no pool at all. Each connection is a new TLS
  connection with a one-stream session. The reference client is required to
  reuse sessions, and a server may refuse otherwise.

## The hook

`TcpClientHandler` and `ProxyConnector` gain:

```rust
async fn try_reuse_tcp_stream(&self, target: &ResolvedLocation)
    -> Option<io::Result<TcpClientSetupResult>>;   // default: None
```

- `None`: no live session, so the caller dials as before.
- `Some(Ok(stream))`: a stream opened on a session the handler holds.
- `Some(Err(e))`: the session is live but refused this target (NaiveProxy's
  non-200 answer). A new connection would be refused too, so this is the
  connection's error.

A session that turns out to be dead (the driver ended, a GOAWAY or I/O error,
or a closed sender) is cleared and answers `None`, so the caller dials.
Retrying on a dead session is the case that has to be invisible.

**Wrappers forward.** `TlsClientHandler` with a default inner handler forwards
the question inward. The session already rides on a TLS connection that this
handler made, so a reused stream means no new TLS handshake either. Vision
does not multiplex and answers `None`. Other wrappers keep the default until
one of them carries a multiplexing protocol.

**The chain asks first.** `ClientProxyChain::connect_tcp` asks the selected
hops, from the exit backwards, before it dials: each subsequent hop, then the
initial proxy hop. The first hop that answers carries every hop below it, so
the hops after it run on the stream it returned, and nothing below it is
dialled. Pool selection is unchanged: the question goes to the member already
selected for this connection.

UDP still dials. AnyTLS's UoT rides a session too, and gets the same hook when
its pool lands; NaiveProxy has no UDP.

## NaiveProxy (PR 3.5a)

- `NaiveClientSession::is_ready` is "the driver task has not finished, and no
  request found the connection gone". A failed `send_request`, or a response
  error that is a GOAWAY or an I/O error, marks the session broken; a reset
  of one stream does not.
- `try_reuse_tcp_stream` opens a CONNECT on a ready session. If that fails and
  the session is no longer ready, it clears the slot (only if the slot still
  holds that session) and answers `None`.
- `setup_client_tcp_stream` (a fresh transport) always builds a new session
  on it and stores it. It no longer reuses: being handed a transport means
  the chain found nothing live.
- Every stream holds its session's connection driver, so a session replaced in
  the slot, or never stored, keeps serving the streams it opened.

## AnyTLS (PR 3.5b)

The reference client (`sing-anytls` `client.go:70-138,201-242`):

- A pool of idle sessions keyed by sequence, the newest idle first.
- Idle sessions reaped after 30 s, keeping `min_idle_session` of them.
- `UpdatePaddingScheme` applied to the client's padding factory, as an
  `Arc<ArcSwap<PaddingFactory>>` shared by its sessions.
- Unknown commands skipped rather than fatal (AT-A3), and the padding range
  draw corrected (AT-A4).

`try_reuse_tcp_stream` takes the newest idle session from the pool and opens a
stream on it. A session goes back to the pool when its stream ends.

## Tests

- Chain: a live session at the first hop connects without dialling (the mock
  socket fails if dialled). A session at a middle hop skips the hops below it
  and runs the hop after it on the reused stream. With nothing live, the
  chain dials.
- NaiveProxy, against an `h2` server on loopback: a second connection reuses
  the session over one TCP connection; after the server drops the connection,
  the dead session is cleared and not offered again; a stream outlives its
  session being replaced in the slot.
- Interop: shoes against sing-box's NaiveProxy inbound, including a server
  restart mid-run.
