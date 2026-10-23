# Android AAR

A Gradle library module wrapping the native library:
`src/main/java/com/shoesproxy/ShoesNative.kt` is the Kotlin JNI bridge,
KDoc'd, and the only Kotlin. The JNI entry points it binds are in
`../src/ffi/android.rs`; the contract is in `../MOBILE.md`.

## Commands

Needs `ANDROID_NDK_HOME` (or `ANDROID_HOME` with an NDK), `cargo-ndk`,
Gradle 8.6 or later on the path (CI uses 9.5.0), and Java 17 or later.

```bash
bash scripts/build-android.sh            # output/android/shoes-release.aar
# Native libraries only, skipping Gradle:
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 21 \
    -o android/src/main/jniLibs -- build --profile release-mobile --lib \
    --features control-stats
# Lint the Android target:
cargo ndk -t arm64-v8a -- clippy --locked --lib --features control-stats -- -D warnings
```

Gradle may be absent on a development machine; then verify the native half
with the `cargo ndk` commands and let CI's `Build Mobile Libraries` job (on a
tag, or run by hand) produce the AAR.

## Rules

- Ship `arm64-v8a`, `armeabi-v7a` and `x86_64`; the last so the stock
  emulator can load the library at all. No 32-bit x86.
- `control-stats` is on in every shipped build; `getStats()` returns null
  without it, and the size baseline is recorded with it.
- A JNI signature change is made in `../src/ffi/android.rs`, here, and in
  `../MOBILE.md` in the same commit, and the AAR content check in
  `.github/workflows/mobile.yml` is run by hand before tagging, since nothing
  else compiles the Android targets.
- The socket protector callback runs for every outbound socket; a `protect`
  that returns false must fail the connection, never fall through.
