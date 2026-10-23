# shoesd, the privileged daemon

The host-side helper that owns the TUN device, routes and DNS for the desktop
clients, driven over a local socket with the protobuf contract in
`proto/shoes/daemon/v1/daemon.proto`. `docs/LINUX.md` and `docs/MACOS.md` describe what each
platform's install does, what has not been verified on a device, and why;
`ROADMAP.md`, "Desktop clients", item 4, is the IPC contract's record.

## Commands

`protoc` must be on the path (`brew install protobuf`, or the distribution's
`protobuf-compiler`).

```bash
cargo clippy --locked --features daemon --bins --tests -- -D warnings
cargo test --locked --features daemon --bin shoesd
cargo test --locked --features daemon
```

CI runs the daemon tests on Linux, macOS and Windows; Windows has its own
service and security modules (`win_*.rs`, `auth_windows.rs`), so a change to
`auth.rs` or `install.rs` needs its Windows twin considered.

## Rules

- The daemon authenticates its caller before acting (`auth.rs`), and refuses
  rather than guesses: a uid in more groups than it will read is refused,
  not truncated. The root `AGENTS.md` security rules apply to what a refusal
  logs.
- Anything the daemon changes on the host (routes, DNS) is recorded in
  `AppliedState` so a crash or a kill can be undone on the next start;
  `docs/LINUX.md`, "What the kernel cleans up, and what the record is for",
  says what each platform's kernel reverts by itself and what the record is
  for.
- The protocol is versioned by package (`v1`). A change that breaks a
  desktop client is a new package version, not an edit to `v1`; say so in
  the changelog either way.
- `getgrnam`, `getgrgid` and `getpwuid` answer from one process-wide buffer;
  a test that reads them holds `auth::group_db_test_lock()`.
