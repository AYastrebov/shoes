# The FFI surface

`common.rs` is the platform-independent core (`start_from_config`,
`stop_service`, the one `SESSION`); `android.rs` the JNI entry points;
`ios.rs` the C entry points; `stub.rs` the no-op desktop build. The contract
the callers rely on is in `MOBILE.md` (lifecycle, threading, the C header
`include/shoes.h` as the authoritative signature list), and the mobile
defects are numbered there.

## Commands

These paths are behind `cfg(any(target_os = "android", target_os = "ios",
feature = "ffi"))`, so the default gate does not compile them. Run, in
addition to the root gate, whenever you touch this directory, `src/tun/`,
`src/socket_protector.rs` or `src/config/mod.rs`:

```bash
cargo clippy --locked --lib --tests --features ffi,control-stats -- -D warnings
cargo test --locked --features ffi
cargo clippy --locked --lib --target aarch64-apple-ios -- -D warnings
cargo ndk -t arm64-v8a -- clippy --locked --lib --features control-stats -- -D warnings
```

Moving the socket protector out of `tun::platform` once left duplicate
definitions and a stale import behind while the ordinary gate stayed green.

## Rules

- A change to a C or JNI signature regenerates `include/shoes.h`
  (`scripts/build-apple.sh` runs cbindgen), updates
  `android/src/main/java/com/shoesproxy/ShoesNative.kt`, the Swift wrapper in
  `swift/Sources/ShoesTunnelCore`, and the FFI table in `MOBILE.md`, in the
  same commit. The changelog names it as a surface change.
- `control-stats` is what the mobile builds ship with; the size baseline
  (`mobile-size-baseline.txt`, checked by `.github/workflows/mobile.yml`) is
  recorded against it. Measure a size change the same way.
- A protector that refuses a socket fails the operation (root `AGENTS.md`,
  Security). The doubles in `src/socket_util.rs` act only for the installing
  thread, which is what keeps unrelated tests from failing at random.
- Callbacks run off the caller's thread: `protect(fd)` is invoked from
  whichever runtime thread creates the socket and must not block; the
  traffic callback fires from a Tokio task, never the main thread; `stop`
  blocks and must not be called on the main thread. One function in
  `common.rs` installs the protector and traffic callback, and `stop` clears
  both only after the engine has wound down (`MOBILE.md`, Threading
  contract). Do not retain objects across a stop/start cycle.
