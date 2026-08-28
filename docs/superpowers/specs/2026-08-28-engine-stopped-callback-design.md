# The engine tells the host when it stops

Written 2026-08-28 against `mobile` at `9892385` (after the ShoesTunnelHost
split, before 0.2.16), in answer to KVN's Apple-integration list: items 1
(push errors instead of a health-check poll), 3 (host-side `ShoesError`
cases) and 4 (errors over the app-message channel).

## Why

Today the provider learns that the engine died from a 30-second health
check (`ShoesPacketTunnelProvider.healthCheckInterval`): a tick sees
`shoes_is_running() == false`, reads `shoes_get_last_error`, calls
`report(error:)` and `cancelTunnelWithError`. Up to thirty seconds of a dead
tunnel, then a host that has to write the reason to an App Group file and
post a Darwin notification because nothing on the message channel carries
errors. `ShoesTunnelManager.send` throws `.engine("no tunnel session")` for
conditions that are the host's, so an app maps errors by string.

The engine already knows the instant it stops: `control::start`
(`src/control/mod.rs:222`) calls `on_error` when the service task ends with
`Err`. It does not report an `Ok` end, does not survive a panic, and the FFI
only stores the message for the next poll. The fix is to make that moment a
callback and carry it through to the app.

## Rust: one exit hook, fired for every exit the host did not ask for

`control::start` takes `on_exit: impl FnOnce(Option<String>) + Send +
'static` instead of `on_error`. It is called from a drop guard wrapped
around the service task, so it runs whether `run_prepared` returns `Ok` or
`Err`; `Some(message)` for an error, `None` otherwise. `ServiceHandle`
gains a `stop_requested: Arc<AtomicBool>`; `control::stop_handle` sets it
before signalling `shutdown_tx`, and the guard does not call `on_exit` when
it is set. A stop the host asked for is a stop the host knows about.

Order inside the guard: store `running = false`, then call `on_exit`.
`stop_handle` waits for the engine by polling `running`
(`src/control/mod.rs:108-113`, five seconds); a callback that calls
`shoes_stop` -- which `fire_stopped` below explicitly permits -- would
otherwise spin for the whole timeout. It also means `shoes_is_running()`
is already false when the callback runs, which is what a host expects.

A panic does not reach the guard. The crate builds with `panic = "abort"`
(`Cargo.toml:187`: "a panic is the last thing the process does"), so a
panicking task takes the extension with it and the app sees
`.disconnected` with no callback. The test profile unwinds regardless of
that setting, so no test is written for the panic path; it would pass and
describe nothing that ships.

`run_prepared`'s only `Ok` return today is the shutdown signal, so `None`
is reserved for a future `Ok` that is not one; the callback treats it as
"stopped without a reason". That property is a test, not prose (see
Tests), because it is what keeps `None` from meaning "requested stop" some
day.

Both FFI platforms keep the current `set_last_error` behaviour by wrapping:
`ios.rs` passes `|reason| { if let Some(m) = &reason { set_last_error(m) }
fire_stopped(reason) }`; `android.rs` passes the same without
`fire_stopped`. The JNI surface does not change this round.

The two callers are `src/ffi/ios.rs:295` and `src/ffi/android.rs:292`;
nothing else calls `control::start`.

## C ABI: `shoes_start_with_fd` changes in place

```c
/**
 * Called once, from a Rust thread, when the engine stops without
 * `shoes_stop` having been called: a failure, or a task that ended on its
 * own. `reason` is the failure message, or NULL when there is none; it is
 * valid for the duration of the call only. Never called for a stop the
 * host requested, and never after `shoes_stop` has returned. Runs on a
 * shoes worker thread; do not block in it. `shoes_is_running()` is
 * already false when it runs, and calling `shoes_stop` from inside it is
 * allowed.
 */
typedef void (*ShoesStoppedCallback)(const char *reason);

long shoes_start_with_fd(const char *config_yaml,
                         int device_fd,
                         ProtectSocketCallback protect_callback,
                         ShoesTrafficCallback traffic_callback,
                         ShoesStoppedCallback stopped_callback);
```

- `shoes_start` (no descriptor) is unchanged; it has no known consumer and
  Android enters through JNI. The surface count stays at 12; the CHANGELOG
  says the `_with_fd` signature changed and why that is acceptable one
  release after it appeared.
- `stopped_callback` may be NULL, in which case nothing is called.
- The slot is `STOPPED_CALLBACK` in `ios.rs`, the same
  `OnceLock<RwLock<Option<Arc<dyn Fn(Option<String>) + Send + Sync>>>>`
  shape as the traffic callback in `src/tun/traffic.rs`. It is installed
  before `control::start`, like the traffic callback, and cleared on the
  failed-prepare branch (`ios.rs:284`) before returning -1. `shoes_stop`
  clears it *before* `stop_service`, so a requested stop is silent at both
  layers. That is the opposite order from the traffic callback, which
  `shoes_stop` clears after (`ios.rs:335-337`) -- a traffic tick during
  shutdown is harmless, an exit event during a requested shutdown is the
  thing this slot must never deliver. The traffic order is left as it is.
- `shoes_start` (no descriptor) shares the start path and installs an
  empty stopped slot, so a callback left by an earlier `_with_fd` session
  can never fire for it.
- The callback runs on a worker of the two-thread iOS runtime and must not
  block, the same rule the traffic callback carries; the Swift side hops
  to the actor, but the C doc is the contract.
- `fire_stopped` takes the slot's `Arc` out under the lock, releases the
  lock, then calls, so a callback that itself calls `shoes_stop` cannot
  deadlock. It also copies the reason into `LAST_ERROR` first, so
  `shoes_get_last_error` after the callback still answers.

## Swift, `ShoesTunnel`

- `ShoesEngine.start(_:deviceFD:onTraffic:onStopped:)` gains
  `onStopped: @escaping @Sendable (String?) -> Void`, required. No default:
  a default that swallows the death is the bug this change removes. A
  failed start never calls it.
- `TrafficCallbackBridge` becomes `CallbackBridge` with two slots
  (`traffic`, `stopped`) under the one lock and two `@convention(c)`
  globals. Its doc comment, which today says "do not add a second global
  instead of reaching for this", is rewritten: both C callbacks share the
  one process-global object; a third callback goes in here too.
- `ShoesPacketTunnelProvider`:
  - `startEngine` passes an `onStopped` that hops to the actor and calls
    `engineStopped(reason:)`. That method ignores the event while
    `isRebinding` (a rebind stops the engine on purpose and the slot is
    cleared before that stop anyway) or after `stopTunnel` began; else it
    builds `ShoesError.engineStopped(reason)`, records it, logs it, calls
    `report(error:)`, then `cancelTunnelWithError`.
  - The health check is removed: `healthCheckInterval`, `healthCheck`,
    `startHealthCheck()` and the tick loop. It could only notice what the
    callback now reports, thirty seconds later. The equivalence is exact:
    both observe the service task ending. A hang where the task lives but
    nothing flows was invisible to `shoes_is_running()` too, so nothing is
    lost there -- and nothing is gained; that failure mode stays
    unobserved. `healthCheckInterval` was
    `open`; a subclass that overrode it stops compiling, which is the
    honest signal that the override no longer does anything.
  - `lastError: ShoesError?` on the provider, set at the three
    `report(error:)` sites (failed start, failed rebind, engine stopped),
    cleared when a start succeeds.
  - `report(error:)` doc gains: after an engine death the provider cancels
    the tunnel and the extension process exits; a host that needs the
    reason in the app must persist it from this hook, because the message
    channel below cannot answer once the process is gone -- and a Rust
    panic aborts without any hook at all, which is one more reason the
    app must treat a bare `.disconnected` as a possible failure.

## Swift, `ShoesTunnelCore`

- `ShoesError` gains three cases:
  - `.noSession` — `ShoesTunnelManager.send` with no
    `NETunnelProviderSession` ("no tunnel session");
  - `.providerNoReply` — the session returned no data ("provider gave no
    reply");
  - `.engineStopped(String?)` — the callback above ("shoes stopped:
    <reason>" or "shoes stopped").
  `.engine(String)` remains for an FFI call other than start that returned
  failure. `ShoesTunnelManager.send` throws the two host cases instead of
  `.engine`. Adding cases breaks a consumer's exhaustive `switch`; the
  CHANGELOG says so.
- `ShoesError: Codable`, encoded as `{"kind": <case name>, "message"?,
  "seconds"?}` with the same hand-written keys style as `ShoesAppMessage`,
  and decoding an unknown `kind` throws (so a newer provider's case reaches
  an older app as a decode error, not a wrong case).
- `ShoesAppMessage.lastError` → `ShoesAppReply.lastError(ShoesError?)`.
  Wire: `{"kind":"lastError","error":{...}}`, `"error":null` when none.
  The provider answers it from `lastError`. Documented limit: it answers
  for a failed rebind or any error while the extension is alive; after an
  engine death the process is gone and the app sees only
  `.disconnected`, so a host still persists fatal reasons from
  `report(error:)`.

## Tests

- Rust, `src/control/mod.rs`: `on_exit` fires with `Some` when
  `run_prepared` fails; does not fire after `stop_handle`; `running` is
  already false when it fires (the callback asserts it). A test that a
  `run_prepared` ended by the shutdown signal returns `Ok(())` and one
  ended any other way does not, so `None` cannot come to mean "requested
  stop" without a test going red. `src/ffi/ios.rs`: `shoes_stop` before an exit
  leaves the slot empty and the callback uncalled; a failed
  `shoes_start_with_fd` never calls it.
- Swift Core: `ShoesError` Codable round-trip for every case, including
  `.engineStopped(nil)` and `.timedOut(seconds:)`; unknown `kind` throws;
  `.lastError` message and reply round-trip including `nil`.
- Swift `ShoesEngineTests`: existing start tests gain the parameter; a
  failed start (descriptor 7, bad config) does not call `onStopped`.
- The link check is untouched: Host never sees the FFI.

## Docs and release

- `include/shoes.h`: the typedef and the changed prototype, documented as
  above.
- `swift/README.md`: "Everything else is inherited" lists "the engine's
  stop callback" in place of "a health check"; the app section shows
  `try await tunnel.send(.lastError)`.
- CHANGELOG under `Unreleased`, beside the split entry: the callback, the
  removed health check, the `ShoesError` cases (source-breaking for
  exhaustive switches and for `healthCheckInterval` overrides),
  `ShoesEngine.start`'s new parameter, the `_with_fd` signature change.
- Then `release-apple.yml` cuts 0.2.16 with both entries.

## Out of scope

The JNI/Kotlin stop callback for Android; pushing stats through a callback
(item 2); log rotation (5); the path-change filter (6); the compiled log
ceiling (8).
