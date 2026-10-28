# A stopped listener for Android, and a session id on both platforms

On Android, shoes stopping on its own -- a fatal error in its runtime, a
task that ended -- is something the host can only discover by polling
`isRunning()`. KVN's `LivenessWatch` (KVN#42) does that every two seconds,
and spends two classes and thirteen tests making sure a poll can never
mistake a requested stop or a reconnect for a death. iOS has had a stopped
callback since `shoes_start_with_fd`; the delivery machinery is shared in
`src/ffi/common.rs` and Android's `start` simply installs nothing in it.
This change gives Android the callback, and gives both platforms a real
session id so a host can tell a death from a session it has already
replaced.

Written 2026-10-28 against `mobile` at `ef176d9e` (v0.8.4 + 2). The
consuming client is KVN's Android app; its workaround and the gap it names
are in KVN#42's description and `docs/architecture/android.md` there.

## Problem

When shoes stops on its own on Android the app shows Connected over a TUN
nothing reads, and every packet is dropped in silence. Nothing in shoes
tells the host: `start` returns before the engine runs, `stop` is the
host's own act, and the one channel for an unrequested end is
`getLastError()` becoming non-null, which has to be polled. A poll costs a
wake every interval for the life of a session, carries a window of that
interval where the UI lies, and has to be sequenced against the host's own
stops so a stop is never reported as a death -- which is the whole of
KVN#42's `SessionRegistry`.

Two things make the poll the host's only option:

1. **No stopped callback on Android.** `Java_com_shoesproxy_ShoesNative_start`
   calls `common::start_session(.., None)` (`src/ffi/android.rs:366`), with
   a comment saying the host polls. iOS passes `on_stop(stopped_callback)`
   (`src/ffi/ios.rs:360`), a one-shot `FnOnce(&ExitReason)` the session
   owns. `common::fire_stopped` records the reason for `get_last_error`,
   then takes the callback out of the session under the lock and calls it
   with the lock released; `stop_service_locked` takes the whole session
   out before it waits, so a requested stop never reaches the callback.
   Nearly every property the Kotlin side had to build itself already holds
   in that code; the one that does not is the race in change 4.

2. **No session identity.** `start` returns the literal `1` on both
   platforms and `stop(handle)` ignores its argument (`MOBILE.md`, item 5).
   A host that consumes engine events asynchronously -- KVN's controller
   does -- can apply a death from one session to the one that replaced it,
   the "known gap" KVN#42 leaves open, because nothing in the event names
   the session it is about.

The desktop paths do not have either problem. `shoesd`'s supervisor passes
`control::start` an exit closure that posts `Command::EngineExited` onto
its own channel (`src/bin/shoesd/supervisor.rs:443-447`), and `WatchStatus`
streams the resulting transition to the GUI; the macOS Network Extension
uses the same C API as iOS and hands `shoes_start_with_fd` a stopped
callback (`swift/Sources/ShoesTunnel/CallbackBridge.swift:63`). Only the
Android JNI surface is behind.

## Scope

The Android JNI entry points and the Kotlin bridge; the shared session in
`src/ffi/common.rs`; the handle both platforms return and what `stop` does
with it; the Swift wrapper's use of that handle. No change to the engine,
the daemon, the C callback types, or the Swift package's public API. The
iOS stopped callback keeps its signature; only the value `shoes_start*`
returns and what `shoes_stop` does with it change there.

## What the references do

The reference for this contract is shoes' own iOS surface, which is already
in production under KVN's macOS provider:

- `ShoesStoppedCallback` (`src/ffi/ios.rs:62-83`, `include/shoes.h:40-63`):
  called once, from a shoes worker thread, when the engine stops without
  `shoes_stop` having been called; never for a requested stop and never for
  a failed start; `shoes_is_running()` is already false when it runs; the
  reason is the same text `shoes_get_last_error` returns afterwards; a call
  in flight when `shoes_stop` begins may complete after it returns; calling
  `shoes_stop` from inside it is allowed; calling `shoes_start` from inside
  it is refused with an error, since the callback runs on a worker of the
  dying session's runtime and a `block_on` there would abort the process.
- `CallbackBridge.deliverStopped` (`CallbackBridge.swift:46-55`) takes its
  slot rather than reading it, so the Swift side also calls at most once
  per session. That is the host-side half of "at most once": the library
  guarantees one call per session, the host guarantees it acts once.
- The Android traffic callback (`src/ffi/android.rs:300-316`) is how a
  Rust worker thread reaches a Kotlin object: a `Global<JObject>` held in an
  `Arc`, `JavaVM::attach_current_thread`, `call_method` by name and
  signature, the `Result` discarded. The stopped listener is called the
  same way, once.

## What changes

1. **`ShoesNative.StoppedListener`** -- a Kotlin functional interface,
   `fun onStopped(sessionId: Long, reason: String)`, beside
   `TrafficListener`. The native `start` takes it as a fourth parameter,
   nullable; a non-external three-argument `start` overload passes null, so
   every existing caller compiles and behaves as before. One native symbol
   named `start`, so the JNI export's name does not change and the count the
   macOS surface check reads is untouched (that check is of the C surface,
   which does not change at all).

2. **The listener is the session's `on_stop`.** `android.rs` builds a
   `StoppedCallback` that attaches the current thread to the JVM and calls
   `onStopped(sessionId, reason)`, the reason converted with the same
   lossy rule as every other string crossing this boundary, and passes it
   to `start_session`. The global reference to the listener is owned by the
   closure and dropped after the call; a JNI failure or a Java exception
   thrown by the listener is logged and cleared, never propagated: the
   thread it runs on belongs to a runtime that is already ending. Every
   sentence of the iOS contract above applies verbatim and is written on
   the Kotlin interface: at most once, never for a requested stop or a
   failed start, `isRunning()` already false, `getLastError()` carries the
   same text, do not block in it, `stop` from inside it is allowed, `start`
   from inside it is refused with an error (`refuse_start_from_runtime_thread`
   already does this for a caller on a runtime thread; the test in
   `ios.rs` covers the path).

3. **A session id, on both platforms.** `common::Session` gains an `id`,
   taken from a process-wide counter that starts at 1, so the first session
   of a process returns what every session returned before. `start_session`
   returns it; `shoes_start`, `shoes_start_with_fd` and the JNI `start`
   return it instead of the literal `1`. The id is what the Android
   listener is handed. The iOS callback's C signature does not change;
   a Swift host that needs the id has it from `shoes_start_with_fd`'s
   return and the slot-taking bridge already keeps one session's death
   from reaching another's handler.

   A consequence hosts must know: a stop issued before `start` has returned
   cannot name the session that start is making. KVN's Android
   `ShoesSession` records such a stop and carries it out when the start
   returns, with the handle it got; the Swift wrapper in this repository
   waits for the in-flight start itself (change 6). Both headers say so.

4. **An exit names the session it is for.** Today an exit and a start can
   cross: `ExitGuard::drop` (`src/control/mod.rs`) marks the service
   stopped before it calls `on_exit`, and `is_service_running()` reads
   that flag, so a `start` on another thread passes the already-running
   guard in that window and replaces the slot. `fire_stopped` then writes
   the old session's reason over the error the new start just cleared, and
   takes the successor's `on_stop` and calls it with the old session's
   reason -- the misattribution the id is meant to prevent, inside the
   library. The fix: the exit closure handed to `start_and_install`
   captures its own id (`move |reason| fire_stopped(id, reason)`), and
   `fire_stopped` compares it with the slot's. On a match it records and
   delivers as today. If the id is the one a stop has taken out of the
   slot and is waiting on, the exit is the exit guard's losing race -- a
   real failure that landed as the host reached for the switch, or the
   stop's own unrequested-end echo -- and is recorded for `get_last_error`
   without a callback, so the stop's existing echo rule
   (`written_by_the_stop`, from an earlier fix that kept such a crash
   visible) still judges it. Otherwise, a mismatch or an empty slot with
   no stop waiting, it is dropped: the session that exited is gone and the
   one in the slot is someone else's; it logs at warn naming both ids.
   Tests: session B installed, A's exit fired, B's callback untouched and
   `get_last_error` unchanged; a session that fails while its stop waits
   leaves the failure in `get_last_error` and calls no callback; the echo
   variant restores the earlier error.

5. **`stop(handle)` acts on that session only.** `stop_service_locked`
   takes the id: if it names the running session, the stop proceeds as
   today; if a session is running under another id, or none is, the call
   is a no-op that returns released (`true` / `1`) with a warning in the
   log naming both ids. Released is the truth for a session that is gone:
   its engine exited or was stopped before, and its descriptor is the
   host's to close. This is what lets a host "release by identity", as
   KVN#42's `ShoesSession.stop(pfd)` does by hand: a late death handler
   can call `stop(oldId)` without touching the session that replaced it.
   The cost is one host mistake the old behaviour tolerated -- passing a
   constant rather than the value `start` returned, which the old
   documentation's "returns 1" invited -- now stops nothing. Both
   headers say so in the line that documents the parameter, and MOBILE.md
   item 5 closes with this.

6. **The Swift wrapper keeps the handle.** `ShoesEngine.start`
   (`swift/Sources/ShoesTunnel/ShoesEngine.swift:76-84`) discards what
   `shoes_start_with_fd` returns, and `stop()` (`:100-103`) calls
   `shoes_stop(1)`, with the class comment saying the handle is ignored.
   That is the constant-handle mistake change 5 stops tolerating, and it is
   in this repository. KVN's Android `ShoesSession` already stores what
   `start` returns and passes it to `stop` (its `shoesHandle`, zeroed
   after), so the other consumer needs nothing. The engine stores the
   handle in a locked slot when
   `start` succeeds, `stop()` passes it and clears it, and a `stop()` with
   no handle (never started, or already stopped) passes 0, which the
   library answers with released, so the provider's
   `if engine.isRunning { await engine.stop() }` call sites keep working.
   A `stop()` that arrives while `start` is still inside the native call
   waits for that call and then stops the session it made: before this
   change `shoes_stop(1)` queued behind the start and stopped whatever ran,
   and a stop that passed 0 instead would have left the engine running
   after `stopTunnel` returned. The start task records the id itself, so
   a waiter finds it set. The native start and stop are injectable on a
   test instance so this sequencing is tested without the library.
   The class comment is corrected. The package's public API (`start`,
   `stop`, `isRunning`) does not change, so a consumer such as KVN's macOS
   provider needs nothing.

7. **Documentation.** `MOBILE.md`: the FFI surface table (`start` with its
   fourth parameter, its return, `stop`'s rule), the lifecycle contract
   (step 4, and a new sentence in the Android column of "Error reporting":
   the listener, with polling `getLastError()` kept as the fallback for a
   host that passes none), the threading contract (the listener runs where
   the iOS callback runs), item 5 marked fixed. `ShoesNative.kt`: the
   interface, the overloads, and `getLastError`'s KDoc no longer describes
   polling as the only way. `include/shoes.h` regenerated by cbindgen for
   the `shoes_start*` return and `shoes_stop` parameter wording; the
   symbol list is unchanged. `CHANGELOG.md` under Unreleased.

## Error handling

- A listener that throws: the exception is logged at warn with its
  description and cleared on the attached thread. Nothing else happens; the
  session has already ended and `getLastError()` already holds the reason.
- A JVM that refuses the attach (`attach_current_thread` fails): logged
  and dropped, as the traffic callback does today. The reason is still in
  `getLastError()`.
- `start` failing after the listener reference was taken: the reference is
  dropped with the closure. The existing `fail` closure in `android.rs`
  clears the installed callbacks; the stopped callback is never installed
  on a failed start because `start_session` is the last step and is not
  reached.
- `stop` with an id that is not the running session's: no-op, returns
  released, warns with `stop({given}): the running session is {running}`
  or `no session is running`. Not an error in `getLastError()`: that
  slot is for the engine's reasons, and the host polling it after a stop
  must still read null.
- The id counter is a `u64` AtomicU64 read into a `jlong` / `c_long`;
  it will not wrap in the life of a process.

## Testing

- `src/ffi/common.rs` tests, which compile on the host with `--features ffi`
  and run in CI's macOS FFI job:
  - two sessions installed in turn get increasing ids, the first of a
    process being 1 cannot be asserted across tests sharing a process, so
    the test asserts strictly increasing;
  - `stop_service_locked` with the running id stops and reports released;
    with a stale id it leaves the session running, reports released, and
    does not touch the callback;
  - an unrequested end delivers the id the session was started with to
    the callback (the `StoppedCallback` signature gains the id alongside
    the reason);
  - an exit from a session that is no longer in the slot (a successor
    installed) neither reaches the successor's callback nor writes
    `get_last_error`;
  - the existing tests -- a requested stop never reaches the callback, an
    unrequested end records then calls once -- keep passing unchanged in
    meaning.
- `src/ffi/ios.rs` tests: `shoes_start_with_fd` still returns -1 on a
  rejected config; the refused-start-from-callback test is unchanged.
- `swift/Tests/ShoesTunnelTests`: a test on a `ShoesEngine(forTesting:)`
  that `stop()` before any start returns true, which exercises the 0-handle
  path against the real library; the engine's existing tests keep passing.
  CI's "Build and test ShoesTunnel" job runs them.
- The Android JNI code cannot run on the host. It is compiled by the
  `aarch64-linux-android` clippy job in `lint.yml` and the AAR build in
  `mobile.yml`; the listener call is one `call_method` with a signature
  string, which the compiler checks against nothing, so the signature
  `(JLjava/lang/String;)V` is checked by reading it against the Kotlin
  declaration in review, as the traffic callback's was. A device run in
  KVN, where the host can be made to see a death by killing the proxy
  server, is the end-to-end check and is KVN's to do; this spec records
  that it has not been done.
- Each new test is watched failing first.

## Out of scope

- Changing the C stopped callback to carry the id: a new typedef and a
  new `shoes_start_with_fd` variant, for a problem the Swift bridge's
  slot-taking already contains. Recorded in `MOBILE.md` item 8 as a
  possible follow-up if a Swift host ever needs it.
- A debug hook to make shoes stop on its own for testing; KVN#42 names the
  lack and this does not add one.
- KVN's side: dropping `LivenessWatch`, or keeping it as a fallback at a
  longer interval, is KVN's decision once a release carries this.
