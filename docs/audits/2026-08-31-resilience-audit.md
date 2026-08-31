# Resilience audit — 2026-08-31, at v0.2.17 (4882547)

Scope: code quality, error handling, and connection recovery across the four
layers a real deployment exercises — the AWG/TUN Rust core, the FFI + control
surface, the Swift package, and the standalone desktop binary. Four parallel
read-only reviews, criticals re-verified by hand against the tree. Line numbers
are against `mobile` at `4882547`.

The one-sentence verdict: **error-driven failures are handled well — silent
failures are not detected anywhere in the stack, and the stop/start state
machines have races at both the FFI and Swift layers.**

## Cross-cutting themes

1. **Silence is invisible.** Every death detector is error-driven: the recv
   streak needs recv *errors*, the endpoint rebind needs a route-gone *errno*,
   the desktop connector's `is_dead()` needs the decapsulate loop to have
   *returned*. A tunnel that handshakes and then goes deaf — expired NAT
   mapping after sleep, server rebooted, path silently changed — is detected by
   nothing, on any platform. Two audits found this independently from opposite
   ends (`src/amneziawg/tunnel.rs` has no inbound-liveness watchdog; the
   connector rebuild at `src/amneziawg/connector.rs:140` can therefore never
   fire for a deaf-but-error-free socket). This is the single highest-value
   fix in the report.
2. **Recovery paths don't retry.** A failed rebind is never retried
   (`endpoint.rs:182-187`); a wake into no-connectivity kills the tunnel
   instead of backing off (provider `:312-316`); a connector rebuild has no
   backoff or failure memoization (`connector.rs:129-202`).
3. **Stop/start state is racy.** The FFI empties `TUN_SERVICE` before the 5 s
   stop wait, so `shoes_is_running()` lies for the whole window
   (`common.rs:106-110`); the Swift provider guards its lifecycle with single
   booleans and no session identity, and none of it is tested.
4. **The send path and Android trail the recv path and iOS.** Send failures
   have no accounting at all; two Android start arms set no `LAST_ERROR` and
   one leaks JNI globals.

## Critical

| # | Finding | Where |
|---|---------|-------|
| C1 | No inbound-liveness watchdog anywhere; a silent-dead tunnel is never detected (mobile: engine reports healthy forever; desktop: post-sleep deaf tunnel is exactly the case the rebuild path cannot see) | `src/amneziawg/tunnel.rs:376-462`, `connector.rs:140` |
| C2 | `WireGuardError::ConnectionExpired` — the REKEY_ATTEMPT_TIME "peer is gone" signal — swallowed at `debug!` | `src/amneziawg/tunnel.rs:741-743` |
| C3 | AWG netstack TCP: no `set_timeout`/`set_keep_alive` (smoltcp default retries forever), `pending_tcp` never swept, no socket cap → app flows hang forever against an unreachable server and each stuck flow holds ~576 KiB → extension OOM under browser retries. TUN-side stack does it right (`stack_common.rs:773-775`) | `src/amneziawg/netstack.rs:347-419` |
| C4 | `stop_service` takes the handle out of `TUN_SERVICE` **before** the 5 s wait → `shoes_is_running()` false mid-stop → a concurrent `shoes_start` passes the guard and runs a second engine on the same fd | `src/ffi/common.rs:106-110` + `ios.rs:288` / `android.rs:186` |
| C5 | Swift: `rebindTunnel()` checks nothing after its awaits — a rebind entered just before `stopTunnel` restarts the engine **after** the stop completion handler returned, on a descriptor the system may have reclaimed | `ShoesPacketTunnelProvider.swift:296-316` |
| C6 | Desktop: editing the config into an invalid state **kills the running proxy** on reload (every reload error arm exits) instead of keeping last-good | `src/main.rs:366-443` |
| C7 | Desktop: EMFILE hot-spins the accept loop at CPU speed with one `error!` line per iteration | `src/tcp/tcp_server.rs:43-49` |
| C8 | Desktop: `--dry-run` failure exits **0** — tooling cannot detect a bad config | `src/main.rs:402-409` |

## Should-fix — reconnection (Rust core)

- Nothing transmits after a rebind; an idle tunnel's inbound stays dead until
  app traffic happens (server still sends to the old source address). Force a
  keepalive from `on_rebound`. `tunnel.rs:324-332`
- Failed rebind never retried; no backoff loop. `endpoint.rs:182-187`
- Desktop has no path monitor at all — `notify_network_change` is FFI-only;
  an idle desktop tunnel never notices a network change. `endpoint.rs:46`
- `Ignore`-class recv errors (`ENETDOWN`/`ENETUNREACH` can be persistent) get
  no backoff → hot spin + per-iteration rebind requests. `tunnel.rs:400-403`
- No send-side error accounting: a permanent send failure (Android `EPERM`
  after lost protection, `ENOBUFS`) = infinite warn lines, healthy status.
  `tunnel.rs:501-512`; also `is_route_gone` omits `EPERM`/`EACCES` and its
  `libc::EINVAL` check is dead on Windows (`endpoint.rs:221`).
- No connect timeout on the outbound TCP path (OS default ~75 s, per address,
  serially). `socket_connector_impl.rs:229`
- Both smoltcp stacks run on `SystemTime` — a backward NTP step on wake stalls
  their timers. `netstack.rs:293`, `stack_common.rs:389`
- UDP session head-of-line blocking: `create_connection` awaited inside the
  session `select!`. `udp_manager.rs:382`
- `udp_to_stack_tx` is unbounded. `src/tun/mod.rs:187`
- Connector rebuild: no backoff/cooldown on repeated failures; a "successful"
  rebuild against a down server is never re-detected (see C1).
  `connector.rs:129-202`

## Should-fix — FFI / control

- Android `Runtime::new()` failure: no `LAST_ERROR`, leaks protector +
  traffic callback (both hold JNI globals). `android.rs:263-269`; JNI
  extraction failure also sets no `LAST_ERROR`. `android.rs:209-216`
- `StopOutcome::TimedOut` discarded at both FFI surfaces — host is told to
  close the fd even when the engine may still be reading it.
  `ios.rs:415`, `android.rs:328`
- Unrequested clean exit sets no `LAST_ERROR` (stale or null read);
  `ENDED_UNREQUESTED` exists but never reaches the FFI. `ios.rs:86-89`,
  `android.rs:298-302`
- `shoes_stop` never clears `LAST_ERROR`; requested-stop race can also write
  one (`stop_requested` store vs. guard read). `control/mod.rs:105/377`
- NUL byte in a reason string → callback gets NULL ("clean stop") *and*
  `shoes_get_last_error` returns NULL. `ios.rs:95-98`, `:543-547`
- `shoes_start` from inside the stopped callback aborts the process
  (`block_on` inside a runtime) — the natural auto-reconnect pattern, not
  warned against. `ios.rs:351`, doc at `:48-61`
- `panic="abort"` is only on `release-mobile`; a plain `--release` FFI build
  reports a panicking engine as a clean stop and unwinds across `extern "C"`.
  `Cargo.toml:163-166` vs `:186-187`
- `.expect` on stack-thread spawn is reachable under extension memory
  pressure → aborts the host app. `stack_common.rs:255`

## Should-fix — Swift lifecycle

- No `sleep(completionHandler:)` override — `wake()` delivery is not
  guaranteed without it (WireGuard-family providers override it as a no-op
  precisely for this); `wake()` is also unguarded by `isStopping`.
  Provider `:109-114`
- Engine death during a path change beats the 500 ms debounced rebind —
  the most common mobile event can tear down instead of recover; the removed
  `isRebinding` guard's justification has a hole (the Task hop can deliver an
  old session's death mid-rebind). Fix with a session ID stamped into the
  stopped closure. `:240`, `:320-331`
- Second path change during an in-flight rebind is silently dropped
  (no re-arm). `:298`
- `loadConfiguration()` sits outside the start-timeout race — a slow subclass
  hangs `startTunnel` until the system's ~60 s kill. `:128`
- `stopTunnel` awaits the engine's full 5 s stop inside the system's ~5 s
  allowance — no margin; and `shoes_stop`'s confirmed/timed-out result is
  discarded (`ShoesEngine.swift:88`).
- App cannot distinguish user-stop / engine-death / system-kill:
  `NEProviderStopReason` is logged and thrown away; no persistence helper for
  the fatal reason despite docs mandating hosts persist it; `report(error:)`
  must be synchronous and the docs don't say so. `:105`, `:57`
- `ShoesTunnelManager.send()` never returns if the extension dies
  mid-request — needs the timeout race the provider already has.
  `ShoesTunnelManager.swift:104-110`
- No on-demand/always-on support, and `start(configure:)` structurally
  prevents it (closure never sees the manager). `ShoesTunnelManager.swift:44`
- macOS: `activate()` hangs forever pending user approval with no signal;
  `.willCompleteAfterReboot` treated as success.
  `SystemExtensionInstaller.swift:37-47`
- **Zero test coverage** for the provider, bridge, manager, and installer —
  every lifecycle finding above lives in untested code.

## Should-fix — desktop

- No SIGINT/SIGTERM handling at all (`main.rs:475` — `TODO: signal handling?`);
  reload aborts all in-flight connections with no drain.
- TCP bind failure = silent task panic, others keep running, exit 0 with a
  missing listener (and "Starting server" printed before the bind); QUIC bind
  failure = process death. Inconsistent. `tcp_server.rs:396`, `quic_server.rs:71`
- QUIC endpoint close ends the accept task silently. `quic_server.rs:86`
- `error!` per failed accept/connection → log flood from scanners.
  `tcp_server.rs:70`
- Unbounded per-connection spawn (no semaphore); log file grows forever with
  `-l` (same `append(true)` pattern as the FFI). `logging.rs:51-56`
- Control API gaps for a tray app: poll-only status, no
  Starting/Reconnecting, tunnel rebuilds invisible to `status()`, unusable
  without a TUN config, and the standalone binary exposes none of it.

## Verified correct (worth trusting)

- Recv-error streak window/backoff, EMSGSIZE classification, counter-wrap in
  the trailer probe, and the fatal generation scheme's three barriers against
  stale reports.
- `sleepyinstant` clock selection and TAI64N stamping across suspend — the
  session self-recovers after long sleep via re-handshake on next transmit.
- WireGuard timer model in awgtun (rekey/reject/keepalive, profile-overridable).
- `is_running() == false` genuinely implies the TUN fd is released, on every
  death path including fatals; iOS `fail`-closure cleanup discipline; lock
  ordering (no cycles found); no non-test unwrap/expect on FFI paths.
- Swift: completion handler called exactly once on all start paths; the
  timeout race's `ClaimFlag`; the stopped-callback at-most-once take-slot;
  no dangling callbacks after deinit; zero force-unwraps in the package.
- Connector rebuild is single-flighted; UDP sessions expire; task
  abort-on-drop discipline in AWG/TUN paths is clean.

## Suggested attack order

1. **Liveness + expiry signals** (C1 + C2, plus post-rebind keepalive): one
   coherent piece of work in `tunnel.rs` — promote `ConnectionExpired` to a
   death/fatal, add a "packets offered but nothing received for N s" watchdog,
   transmit on rebind. Fixes the mobile silent-death, the desktop post-sleep
   deafness, and the idle-rebind hole at once.
2. **Netstack TCP hygiene** (C3): `set_timeout` + `set_keep_alive` in
   `initiate_tcp`, sweep `pending_tcp`, cap sockets — mirrors what
   `stack_common.rs` already does.
3. **FFI stop/start serialization** (C4) + the LAST_ERROR discipline batch.
4. **Swift lifecycle state machine** (C5 + sleep/wake + session IDs) with the
   provider test scaffold the package currently lacks.
5. **Desktop daemon hygiene** (C6–C8, signals, bind-failure policy).
