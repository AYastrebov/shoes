# The mobile log file rotates, and the library says what level it can log at

Two items from KVN's list in `ROADMAP.md` ("Apple integration: what the first
consumer asked for", Open), which that section asks to ship together. Written
2026-10-10 against `mobile` at `bb1d4fd`.

## Table of Contents

- [Problem](#problem)
- [Design: rotation](#design-rotation)
- [Design: the compiled ceiling](#design-the-compiled-ceiling)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

**The log file grows forever.** `shoes_set_log_file` (C) and
`ShoesNative.setLogFile` (JNI) both reach `ffi::common::setup_log_file`, which
opens the path with `create(true).append(true)`, and
`logging::DynamicFileLogWriter` appends every line to it. On iOS the file lives
in the App Group container and outlives the extension process, so it grows
across every session for the life of the install. Truncating it when it is set
is the wrong fix: the host sets it once per start, and the previous session's
log, the one that ends in a crash, is the one worth reading.

**A support session asks for logs the build cannot produce.** Every artifact is
built with `log`'s `release_max_level_info` feature (`Cargo.toml`), so `debug!`
and `trace!` are compiled out. `shoes_set_log_level("debug")` succeeds and the
library logs one warning saying nothing more will appear, but the host has no
way to ask, ahead of time, what the build can do, so its UI offers a "debug"
switch that changes nothing.

## Design: rotation

`logging::RotatingFile` replaces the bare `File` behind `LOG_FILE`:

- It holds the path, the open file, the bytes written so far and a cap.
- **Opening** appends, as today, and counts the file's existing length. If the
  file is already at or past the cap, it rotates before the first write, so a
  long previous session is kept whole in `.1` rather than being cut mid-line.
- **Writing** a line that would take the file past the cap rotates first:
  the current file is flushed and renamed to `<path>.1`, replacing any earlier
  `.1`, and a new file is created at the path. A single line longer than the
  cap is written whole to the fresh file.
- The cap is `LOG_FILE_MAX_BYTES`, 4 MiB. The files on disk are therefore at
  most about 8 MiB together, and the `.1` always holds the most recent full
  4 MiB before the current file.

Nothing is configurable. The ROADMAP entry asked for "size-capped rotation,
one `.1` kept"; a cap a host can tune is an addition when one asks.

`ffi::common::write_to_log_file` and `flush_log_file` go through the same type,
so every path that writes the file is bounded.

## Design: the compiled ceiling

- C: `const char *shoes_max_log_level(void)`, returning `log::STATIC_MAX_LEVEL`
  spelled the way `shoes_set_log_level` accepts it: `"off"`, `"error"`,
  `"warn"`, `"info"`, `"debug"` or `"trace"`. The pointer is to a static string
  and must not be passed to `shoes_free_string`.
- JNI: `ShoesNative.maxLogLevel(): String`, the same spelling.
- Swift: `ShoesEngine.maxLogLevel: ShoesLogLevel`.
- The app's side: the engine runs in the extension, and a host app reaches it
  only through `ShoesAppMessage`. `.maxLogLevel` asks, and the provider answers
  `ShoesAppReply.maxLogLevel(ShoesLogLevel)`, so a settings screen can find
  out before it offers the switch.

The ROADMAP entry named the Swift property `effectiveLogLevel`. It is
`maxLogLevel` instead, because the value is the build's ceiling, not the level
in effect: a build whose ceiling is `info` running at `error` has an effective
level of `error`. The name says what the number is.

The mapping from `LevelFilter` to the string lives in `ffi::common`, which
both platforms share and which compiles under `cfg(test)`, so it is tested on
every host.

## Error handling

- A rotation whose rename fails (the `.1` path is unwritable, or is a
  directory) truncates the current file instead, so the cap still holds and the
  newest lines are kept. If truncating fails as well, file logging stops: the
  slot is emptied, and the platform's own log (`oslog`, `logcat`) carries on.
  A file that can be neither rotated nor truncated cannot be kept under its cap,
  and an unbounded file is the defect this fixes.
- Write errors are ignored as they are today: there is nowhere to report a
  failure to log.
- `shoes_max_log_level` cannot fail.

## Testing

- `src/logging.rs`, against a temporary directory with a small cap:
  - setting a file under the cap appends and keeps what was there;
  - writing past the cap moves the old contents to `.1` and starts a new file;
  - a second rotation replaces `.1`, so there are never more than two files;
  - opening a file already past the cap rotates it before writing;
  - when `.1` is a non-empty directory, so the rename fails, the current file
    is truncated and stays under the cap.
- `src/ffi/common.rs`: the ceiling's name round-trips through
  `logging::parse_log_level` to `log::STATIC_MAX_LEVEL`.
- Swift (`ShoesEngineTests`, run by `mobile.yml` against the release-mobile
  XCFramework): `maxLogLevel` is `.info`. `ShoesAppMessageTests`: the new
  message and reply round-trip.
- Each Rust test is checked against its defect: never rotating, rotating
  without keeping `.1`, truncating on open, and an unbounded fallback each turn
  their test red.

## Deliberately out of scope

- **A configurable cap or a count of kept files.** See rotation.
- **The desktop binary's log files** (`shoes --log-file`, `src/main.rs`). A
  server's logs belong to its service manager or logrotate.
- **Making `debug` available in release builds.** That is a size and
  performance decision recorded in `Cargo.toml`, not this change.
