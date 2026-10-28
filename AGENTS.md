# shoes

A multi-protocol proxy in Rust: one crate (`src/lib.rs`) behind the `shoes`
binary, the `shoesd` privileged daemon (`src/bin/shoesd/`), and the mobile
libraries that embed it (`src/ffi/`, `android/`, `swift/`). Configuration is
YAML, documented in `CONFIG.md`.

This file holds the rules that apply to almost every change. Each rule's
reason is one clause, because a rule whose reason is missing gets dropped the
first time it is inconvenient. Procedures that only some tasks need are
skills in `.agent/skills/`; subtrees with their own build and contract have
their own `AGENTS.md`.

## Orientation

| Read | For |
| --- | --- |
| `ROADMAP.md` | What is deliberately missing, what each gap costs, and the recorded debt |
| `CONFIG.md` | Every configuration option, with its default |
| `MOBILE.md` | The FFI, lifecycle and threading contracts, and the mobile defects |
| `docs/specs/` | Design documents for shipped work, with the reference sources cited |
| `docs/plans/` | Implementation plans, kept in sync with what landed |
| `docs/audits/` | Audits and reviews; findings carry IDs that commits and the changelog cite |
| `CHANGELOG.md` | One entry per PR under `## Unreleased`, in the voice of the existing ones |

For anything larger than a bug fix, write a spec in `docs/specs/` first, in
the shape of the most recent one: problem, scope, what the references do with
file-level citations, error handling, testing, and what is out of scope.

## Commands

Build and run:

```bash
cargo build --locked --bin shoes
shoes --dry-run examples/<name>.yaml     # parse a config without starting
```

The gate, before claiming anything works. CI (`.github/workflows/lint.yml`,
`test.yml`) runs the same commands, and every configuration is clean and
stays that way; `--tests` is in on purpose, since it catches what the other
passes cannot see.

```bash
cargo fmt --all && cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo clippy --locked --features desktop --lib --bins --tests -- -D warnings
cargo clippy --locked --features daemon --bins --tests -- -D warnings
cargo clippy --locked --features ffi,control-stats --lib --tests -- -D warnings
cargo test --locked
cargo test --locked --features desktop
cargo test --locked --features daemon
```

When you touch `src/tun/`, `src/socket_protector.rs`, `src/config/mod.rs` or
`src/ffi/`, also run the mobile targets; those paths are behind
`cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))`, so the
default build does not compile them at all (see `src/ffi/AGENTS.md`).

## Code style

- `rustfmt` default settings; clippy at `-D warnings` in every configuration.
- `unwrap`/`expect` warn outside tests (`clippy.toml` allows them in tests). A
  file that still uses them carries a file-level allow naming the plan PR
  that removes them.
- The binary links the library, so an item with no caller in some
  configuration is reported there. The shape for an item whose caller is
  compiled out is a narrow allow with the reason, e.g. "called only from the
  FFI".
- `src/config/types/mod.rs` re-exports config types for library users; follow
  the neighbouring pattern rather than deleting a re-export.
- `socket_util::new_tcp_socket` and `new_udp_socket` exclude outbound sockets
  from the VPN route. If you build an outbound socket any other way, call
  `socket_util::protect_outbound` yourself; the AmneziaWG endpoint and both
  DNS paths do. Five sites once did not, and on Android such a socket is
  captured by the tunnel it feeds.
- Per-packet code (`src/quic_outbound/obfs/`, `src/hysteria2/udp.rs`,
  `src/tuic/udp.rs`, `src/routing/`, `src/tun/`): no allocation per packet
  where in-place or a reusable buffer works, no task spawn per packet (one
  worker per session on a bounded channel), every queue bounded with a
  comment saying what a full one does (for UDP, drop), and reject rather than
  truncate when a limit is exceeded.

## Testing

- Test against this repository's own server, in-process:
  `src/quic_outbound/testing.rs` starts it, generates a certificate and spawns
  echo servers. Build the selector with `create_tcp_client_proxy_selector`,
  the function server startup uses, so tests exercise the real routing path.
- Prove a new test can fail. Watch it fail first for the reason you expect.
  For a test that covers a defect, put the defect back afterwards and confirm
  that exactly that test goes red: copy the file aside, plant the defect, run
  the one test, restore the copy. Two real bugs were caught this way that
  reading the code had missed, and one "fix" was shown to be tested by nothing.
- Global state is process-wide: tests run as threads of one process. Scope the
  effect instead of serialising with a mutex (the protector doubles in
  `src/socket_util.rs` act only on the installing thread).
- Keep the suite fast: over 1800 library tests run in about 13 seconds. Bound
  a wait to what proves the point; never wait out a network timeout.
- `assert!(!err.contains(secret))` is a real test: error text gets rewritten
  casually, and a credential creeps back in unnoticed.
- The reuse these tests offer: the UDP router's scripted server-side stream
  (`src/routing/udp_router.rs` tests), the probe matrix (`src/probe_tests.rs`),
  and the KAT fixtures (`tests/data/kat/`, generated by `tests/data/kat/gen/`).

## Security

- Compare secrets in constant time with `subtle::ConstantTimeEq` (`ct_eq`),
  and read every presented value before judging any, so the rejection does not
  say which one was wrong (`src/tuic/server.rs` does this for UUID and token).
  Three authentication paths had drifted to `!=` while four others were right.
- Never put a presented credential in a log line or an error: say that
  authentication failed, not what was sent. Configured secrets go in
  `Redacted<T>` (`src/config/types/redacted.rs`) so `Debug` cannot print them.
- Nothing from a live test enters the repository: no real server's config,
  key, password or address in a fixture, example, commit message or doc, not
  even redacted-looking. Check `git status` before committing after a live
  run (see `.agent/skills/live-interop-check/`).
- Do not hand back something the platform refused. If protecting a socket or
  verifying a certificate fails, fail the operation; returning the object
  turns a loud failure into a silent leak.

## Configuration surface

- An option that is accepted but not implemented is rejected in
  `src/config/validate.rs` with a message that says so. A user who asks for
  `zero_rtt_handshake` and silently gets none believes something false.
- Limits from a reference implementation go in validation with the source
  named (an obfuscation password under four bytes is refused because
  `smPSKMinLen` upstream refuses it).
- Every option reaches `CONFIG.md`, a config in `examples/` that parses, and,
  if it needs no certificate, the smoke loops in `.github/workflows/test.yml`
  (every PR, debug binary) and `.github/workflows/build.yml` (tags and
  nightly, release binary).
  Procedure: `.agent/skills/adding-a-config-option/`.

## Commits and pull requests

- Subject: `area: imperative summary`, lowercase. Body: why, in prose; the
  diff says what changed, the message says what was wrong, what was
  considered, and what was deliberately not done. End with a
  `Co-Authored-By:` line naming the agent and model that wrote it.
- Author email: the one `git config user.email` gives in this clone.
- Commit signing is flaky. `1Password: failed to fill whole buffer` or
  `agent returned an error` means run the same command again; the files stay
  staged. Never work around it by disabling signing.
- When a change closes something in `ROADMAP.md`, `MOBILE.md` or an audit
  table, update that record in the same commit; when it opens something,
  write it down there with what is broken, what fixing it touches, and what
  leaving it costs.
- PRs target `mobile`. Run the gate before opening one; the PR body states
  what was verified and how.
- A live check tests the binary, not the source: rebuild before running one.
  A stale binary once reported a stub error for a feature already implemented.

## Skills

Procedures that only some tasks need, in the
[Agent Skills](https://agentskills.io/specification) format under
`.agent/skills/`. Claude Code reads `.claude/skills/`, which is ignored by
git; `ln -s ../.agent/skills .claude/skills` once per clone.

| Skill | Use when |
| --- | --- |
| `implementing-a-protocol` | Adding or changing a protocol, transport or obfuscation, client or server side |
| `adding-a-config-option` | Adding, renaming or bounding a configuration field |
| `live-interop-check` | Testing against a reference implementation or a real server |

## Where the debt is written down

`ROADMAP.md`, section "Recorded debt", lists what is known and deliberately
left; `MOBILE.md` lists the mobile defects, numbered, with a suggested order
at the end.
