# Android stopped listener and session id: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Android host a stopped listener, give both platforms a real session id, and make `stop(handle)` act only on the session it names.

**Architecture:** The shared FFI session in `src/ffi/common.rs` gains an id and passes it to the exit path and to the stopped callback; the platform files (`android.rs`, `ios.rs`) only adapt their surface to it. Android's listener is one more JNI global reference called through `JavaVM::attach_current_thread`, exactly as the traffic callback is. The Swift wrapper keeps the handle it was discarding.

**Tech Stack:** Rust (jni 0.22, tokio), Kotlin bridge, Swift package, cbindgen for `include/shoes.h`.

**Spec:** `docs/specs/2026-10-28-android-stopped-listener.md`

## Global Constraints

- clippy at `-D warnings` in every configuration, including `--target aarch64-apple-ios` and `cargo ndk -t arm64-v8a` (`src/ffi/AGENTS.md`); `unwrap`/`expect` warn outside tests.
- Ids are `u64`, start at 1, process-wide, strictly increasing; crossed to `jlong` / `c_long` as-is.
- `stop` on a stale or unknown id, 0 included, is a no-op that returns released (`true` / `1`) and warns in the log; it never writes `LAST_ERROR`.
- A late exit (slot empty or holding another id) is logged at warn and neither delivered nor recorded.
- Every exit has a sentence; the Kotlin listener's `reason` is never null. Strings crossing the boundary use `common::c_string_lossy`'s rule (no interior NUL).
- No Cyrillic anywhere. Commit subjects `area: imperative summary`, bodies say why, `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- The C symbol list of `include/shoes.h` does not change (the macOS surface check counts it).
- Each new test is watched failing first.

## Review Focus

- A listener that throws: the exception must be cleared on the attached thread and logged; the session is already gone, nothing else happens. Test: none on the host; the implementer checks `call_method`'s `Err` is handled with `exception_clear` (Task 2 step 3).
- A `start` that fails after the listener reference was taken: the reference drops with the closure, the stopped callback is never installed. Covered by `start_session` being the last step (Task 2 step 3 note).
- `stop(0)` while a session runs: 0 is never an id, so it is the no-op path; a host that passes 0 to mean "whatever runs" gets `isRunning()` still true. Test: Task 1 step 1, `a_stop_with_a_stale_id_leaves_the_session_running` uses 0 as one of the stale values.
- Two starts racing an exit: the exit for the old session must not reach the new session's listener or `getLastError`. Test: Task 1 step 1, `an_exit_for_a_replaced_session_is_dropped`.
- A requested stop whose exit lands mid-stop: still never reaches the callback, and the last-error echo rule (`written_by_the_stop`) is unchanged. Existing test `a_requested_stop_never_reaches_the_stopped_callback` keeps covering it with the new signatures.

---

### Task 1: Session id and exit identity in the shared session

**Files:**
- Modify: `src/ffi/common.rs` (Session, StoppedCallback, start_session, fire_stopped, stop_service_locked, tests)
- Modify: `src/ffi/ios.rs` (`on_stop` adapter, the `1` returns, `shoes_stop`)

**Interfaces:**
- Produces: `pub type StoppedCallback = Box<dyn FnOnce(u64, &ExitReason) + Send>`; `pub fn start_session(_: &Transition, runtime, prepared, on_stop: Option<StoppedCallback>) -> u64`; `pub fn stop_service_locked(_: &Transition, handle: u64) -> bool`; `pub fn is_service_running() -> bool` (unchanged).
- Consumes: `crate::control::start_and_install(runtime, prepared, on_exit, install)`, `ServiceHandle::{is_running, discard}`, `control::stop_handle`.

- [ ] **Step 1: Write the failing tests** in `src/ffi/common.rs`'s `tests` module, beside `install_test_session`. Change `install_test_session` to take and return the id the way `start_session` will (it allocates from the same counter and passes `move |reason| fire_stopped(id, reason)` as the exit), and change `counting()` to record `(id, reason)`:

```rust
#[test]
fn session_ids_increase() {
    let _names = crate::tun::device_name_test_lock();
    let _errors = LAST_ERROR_TEST_LOCK.lock().unwrap();
    let transition = transition_guard();
    let first = install_test_session(&transition, None);
    assert!(stop_service_locked(&transition, first));
    let second = install_test_session(&transition, None);
    assert!(second > first);
    assert!(stop_service_locked(&transition, second));
}

#[test]
fn a_stop_with_a_stale_id_leaves_the_session_running() {
    // locks as above
    let (callback, calls) = counting();
    let id = install_test_session(&transition, Some(callback));
    for stale in [0, id + 1, id.wrapping_sub(1)] {
        assert!(stop_service_locked(&transition, stale), "stale {stale}");
        assert!(is_service_running());
    }
    assert_eq!(calls.lock().unwrap().len(), 0);
    assert!(get_last_error().is_none());
    assert!(stop_service_locked(&transition, id));
    assert!(!is_service_running());
}

#[test]
fn an_unrequested_end_delivers_the_sessions_id() {
    // locks as above; install with a service that ends on its own
    // (see an_unrequested_end_records_then_calls_once for the shape)
    let (callback, calls) = counting();
    let id = install_test_session_that_ends(&transition, Some(callback));
    // wait for the exit as the existing test does
    assert_eq!(calls.lock().unwrap().as_slice(), &[(id, ENDED_UNREQUESTED.to_string())]);
}

#[test]
fn an_exit_for_a_replaced_session_is_dropped() {
    // locks as above
    let (old_callback, old_calls) = counting();
    let old = install_test_session(&transition, Some(old_callback));
    let (new_callback, new_calls) = counting();
    let new = install_test_session(&transition, Some(new_callback)); // replaces the slot, as start_session does
    clear_last_error();
    fire_stopped(old, ExitReason::Failed("late".into()));
    assert!(old_calls.lock().unwrap().is_empty());
    assert!(new_calls.lock().unwrap().is_empty());
    assert!(get_last_error().is_none());
    assert!(stop_service_locked(&transition, new));
}
```

Update the two existing tests to the new signatures (`stop_service_locked(&transition, id)`, callbacks taking `(id, reason)`).

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --locked --features ffi --lib -- ffi::common::tests` (toolchain bin on PATH as `cargo-not-on-path` notes)
Expected: compile errors on the missing id parameter and return type.

- [ ] **Step 3: Implement in `src/ffi/common.rs`**
  - `static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1)`; `fn next_session_id() -> u64` (`fetch_add(1, SeqCst)`).
  - `struct Session { id: u64, handle: TunServiceHandle, on_stop: Option<StoppedCallback> }`.
  - `start_session` allocates the id before `start_and_install`, passes `move |reason| fire_stopped(id, reason)` as `on_exit`, installs `Session { id, .. }`, returns `id`.
  - `fn fire_stopped(id: u64, reason: ExitReason)`: lock the slot; if `Some(s) if s.id == id`, take `on_stop`, release the lock, `set_last_exit`, call `on_stop(id, &reason)`; otherwise `log::warn!("an exit for session {id} arrived after it was replaced (running: {running:?}); dropped")` and return. Record the reason only on the match (today it is recorded first, unconditionally; the order moves inside the match).
  - `stop_service_locked(transition, handle)`: before taking the slot, read its id under the lock; on mismatch or empty, `warn!("stop({handle}): {no session is running | the running session is N}")`, `clear_callbacks` only when the slot is empty (as today), return `true`.
- [ ] **Step 4: Adapt `src/ffi/ios.rs`**: `on_stop` closure signature `move |_id: u64, reason: &ExitReason|`; `shoes_start` / `shoes_start_with_fd` return `start_session(..) as c_long` instead of `1`; `shoes_stop(handle: c_long)` passes `handle as u64` (negative values become huge and never match: fine, documented as "not a handle `shoes_start` returned"). Update the doc comments on the three functions: the return is "the session id, positive; pass it to `shoes_stop`", and `shoes_stop`'s parameter line says a handle that is not the running session's is a no-op that returns 1.
- [ ] **Step 5: Run the FFI tests to verify they pass**

Run: `cargo test --locked --features ffi,control-stats --lib -- ffi::` and `cargo clippy --locked --features ffi,control-stats --lib --tests -- -D warnings` and `cargo clippy --locked --lib --features ffi,control-stats --target aarch64-apple-ios -- -D warnings`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/ffi/common.rs src/ffi/ios.rs
git commit -m "ffi: a real session id, and an exit that names its session"
```
Body: the race (exit guard marks stopped before on_exit; a start can replace the slot in that window), what `stop` now does with a stale id and why, and that iOS's C surface is unchanged.

### Task 2: The Android listener

**Files:**
- Modify: `src/ffi/android.rs` (`start` signature and body, `stop`)
- Modify: `android/src/main/java/com/shoesproxy/ShoesNative.kt`

**Interfaces:**
- Consumes: Task 1's `start_session -> u64`, `stop_service_locked(_, u64)`, `StoppedCallback`.
- Produces: Kotlin `fun interface StoppedListener { fun onStopped(sessionId: Long, reason: String) }`; native `external fun start(configYaml: String, protectCallback: SocketProtector, trafficCallback: TrafficListener, stoppedListener: StoppedListener?): Long`; non-native `fun start(configYaml, protectCallback, trafficCallback): Long = start(.., null)`.

- [ ] **Step 1: Kotlin.** Add the interface with KDoc carrying the iOS contract sentences (once per session; never for a stop you requested nor a failed start; `isRunning()` already false; `getLastError()` same text; shoes worker thread, do not block, marshal yourself; `stop` from inside it is allowed; `start` from inside it is refused with -1 and a reason). Add the fourth parameter to the `external` `start` and the three-argument overload. Update `getLastError`'s KDoc: polling is the fallback for a host that passed no listener. Update `stop`'s KDoc: acts on the session with that id; any other value is a no-op returning true; pass what `start` returned.
- [ ] **Step 2: JNI signature.** `Java_com_shoesproxy_ShoesNative_start` gains `stopped_listener: JObject<'local>` after `traffic_callback`. In the `with_env` block, take a global ref only if `!stopped_listener.is_null()` (`Option<Global<JObject<'static>>>`). The JNI name does not change: one native named `start`.
- [ ] **Step 3: The callback.** Build `on_stop: Option<StoppedCallback>` from the optional ref: `Box::new(move |id: u64, reason: &ExitReason| { ... })` that calls `jvm.attach_current_thread(|env| { let reason = env.new_string(reason.message())?; env.call_method(&*listener, jni_str!("onStopped"), jni_sig!("(JLjava/lang/String;)V"), &[JValue::Long(id as i64), JValue::Object(&reason)])?; Ok(()) })`; on `Err(e)`, `warn!("stopped listener: {e}")` and, inside the attach closure, `env.exception_clear()` when `env.exception_check()` is true (the jni 0.22 names; check `src/ffi/android.rs`'s existing calls for the exact API). The ref is moved into the closure and dropped with it. Pass `on_stop` to `common::start_session`, replace the trailing `1` with `start_session(..) as jlong`, and delete the "No stopped callback: the host polls" comment. Note on failure paths: the `fail` closure runs before `start_session`, so the listener ref is simply dropped.
- [ ] **Step 4: `stop`.** `Java_com_shoesproxy_ShoesNative_stop(.., handle: jlong)` passes `handle as u64` to `stop_service_locked`; update its doc comment (the parameter is used now).
- [ ] **Step 5: Verify on the Android target**

Run: `ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/30.0.16138531 cargo ndk -t arm64-v8a clippy --locked --lib --features ffi,control-stats -- -D warnings`
Expected: clean. Then `bash scripts/build-android.sh` with Gradle on PATH (see memory `cargo-not-on-path`): the AAR builds and `javap -s` on `classes.jar`'s `ShoesNative` shows `start` with descriptor `(Ljava/lang/String;Lcom/shoesproxy/ShoesNative$SocketProtector;Lcom/shoesproxy/ShoesNative$TrafficListener;Lcom/shoesproxy/ShoesNative$StoppedListener;)J` and `StoppedListener.onStopped` as `(JLjava/lang/String;)V`, which is the signature string the Rust side uses.

- [ ] **Step 6: Commit**

```bash
git add src/ffi/android.rs android/src/main/java/com/shoesproxy/ShoesNative.kt
git commit -m "android: a stopped listener on start, and stop by session id"
```

### Task 3: The Swift wrapper keeps the handle

**Files:**
- Modify: `swift/Sources/ShoesTunnel/ShoesEngine.swift:8-18, 76-84, 100-103, 143-148`
- Modify: `swift/Tests/ShoesTunnelTests/ShoesEngineTests.swift` (`stopIsSafeWhenNothingRuns`)

**Interfaces:**
- Consumes: `shoes_start_with_fd` returning the id; `shoes_stop(handle)` no-op on 0.
- Produces: no public API change.

- [ ] **Step 1: Test.** In `stopIsSafeWhenNothingRuns`, assert the return: `#expect(await engine.stop() == true)`. (Runs only on CI's ShoesTunnel job, which links the built XCFramework; record that in the PR.)
- [ ] **Step 2: Implement.** Add `private final class LockedHandle: @unchecked Sendable` beside `LockedFlag` with `func take() -> Int` (returns the value and sets 0) and `func set(_ value: Int)`. In `start`, after `guard handle > 0`, `self.handle.set(handle)`. In `stop`, `let handle = self.handle.take()` before the detached task and `shoes_stop(handle) == 1` inside it. Replace the class comment's "`shoes_stop` ignores the handle it is given" with the rule: `shoes_stop` acts on the session whose id it is given, so this wrapper keeps the id `shoes_start_with_fd` returned and passes it back; 0 after a stop means nothing to stop.
- [ ] **Step 3: Format check.** `swift format lint --strict --recursive swift/` if `.swift-format` is enforced in CI (`mobile.yml`'s swift job); otherwise skip.
- [ ] **Step 4: Commit**

```bash
git add swift/Sources/ShoesTunnel/ShoesEngine.swift swift/Tests/ShoesTunnelTests/ShoesEngineTests.swift
git commit -m "swift: pass shoes_stop the handle shoes_start_with_fd returned"
```

### Task 4: Header, MOBILE.md, changelog

**Files:**
- Regenerate: `include/shoes.h` (`cbindgen --config cbindgen.toml --output include/shoes.h`)
- Modify: `MOBILE.md` (line 23 error-reporting row; FFI surface table 120-135; lifecycle step 4 and the `SESSION` paragraph; threading contract's last bullet; item 5 at 447-462; item 8 gains the "C callback with id" follow-up)
- Modify: `CHANGELOG.md` under `## Unreleased`

- [ ] **Step 1: Header.** Regenerate; `git diff include/shoes.h` shows only comment changes on `shoes_start`, `shoes_start_with_fd` and `shoes_stop`; `grep -cE '^[a-z].*shoes_[a-z_]+\(' include/shoes.h` is unchanged (13).
- [ ] **Step 2: MOBILE.md.** Surface table: `start(configYaml, protectCallback, trafficCallback, stoppedListener?)` returning "the session id, > 0"; `stop(handle)` "released, or no-op true for a handle that is not the running session's". Error-reporting row: Android column gains `StoppedListener.onStopped(sessionId, reason)`, polling `getLastError()` as the fallback. Lifecycle step 4: pass the id `start` returned. The `SESSION` paragraph: "the service handle, its id, and the stopped callback on both platforms". Threading: the last bullet now says "The stopped callback (iOS) and `StoppedListener` (Android)". Item 5: strike-through heading `~~...~~ — fixed`, with the rule and the date. Item 8: a bullet "The C stopped callback carries no session id; a Swift host that needs one has it from `shoes_start_with_fd`'s return."
- [ ] **Step 3: Changelog** under Unreleased, in the existing voice: the listener, the id, the stop rule and its one tolerated-mistake cost, the exit race fixed, the Swift wrapper fix, and that the C symbol list is unchanged.
- [ ] **Step 4: Commit**

```bash
git add include/shoes.h MOBILE.md CHANGELOG.md
git commit -m "docs: the Android stopped listener, session ids, and stop by id"
```

### Task 5: Gate and PR

- [ ] **Step 1:** `cargo fmt --all -- --check`; the seven gate commands from `AGENTS.md`; plus `--target aarch64-apple-ios` and `cargo ndk` clippy.
- [ ] **Step 2:** Prove the defect tests fail against the defect: copy `src/ffi/common.rs` aside, revert `fire_stopped` to the unconditional version, run `an_exit_for_a_replaced_session_is_dropped`, confirm red, restore.
- [ ] **Step 3:** Push `ffi/android-stopped-listener`, open the PR against `mobile` with what was verified and how, naming the Swift test as CI-only and the device run as KVN's.
