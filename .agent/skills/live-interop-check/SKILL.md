---
name: live-interop-check
description: How to test shoes against a reference implementation (sing-box, Xray-core, hysteria, tuic, mieru, naiveproxy, amneziawg) or a real server without leaking credentials into the repository. Use when a task says interop, live test, real server, reference server, or when a protocol change is ready for a check beyond the in-process tests.
---

# Live interop check

## Before

- **Rebuild first.** A live check tests the binary, not the source. A stale
  binary once reported a stub error for a feature that was already
  implemented.

  ```bash
  cargo build --locked --bin shoes
  ```

- **Keep everything outside the tree.** The config, keys, and any capture go
  in a temporary directory outside the working tree (the agent scratchpad,
  or `mktemp -d`). Nothing a real server gave you is written under the
  repository, not even redacted-looking.

## Running a reference

- A reference server for the protocol under test, in a container or as a
  binary, with keys it generated itself (`sing-box generate reality-keypair`,
  `sing-box generate tls-keypair`). The decoy for REALITY can be a sing-box
  `http` inbound with TLS.
- Docker is not installed on the development Mac; Apple's `container` tool
  and native binaries are. Linux references that need a daemon (mieru's
  `mita`) run in a Debian container with a dedicated user.
- Check both directions where both sides exist: our client against the
  reference server, and the reference client against our server.
- Restart the reference mid-run for session-reuse protocols (NaiveProxy,
  AnyTLS): a client that survives only one server lifetime is a defect
  (NA-N1 was found this way).

## The repeatable check

`tests/live_socks.rs` is the check to reach for first: it drives the built
binary with a client config kept outside the tree and proves, in one test
through one child, the four things a tunnel must do (a request by name
exits through the server, one by IPv4 literal is carried, DNS over UDP
ASSOCIATE is answered, eight connections at once complete). It skips itself
without the variables, and refuses to run while something else already
accepts at `SHOES_LIVE_SOCKS`.

```bash
SHOES_LIVE_CONFIG=/outside/the/tree/client.yaml \
SHOES_LIVE_SOCKS=127.0.0.1:11080 \
SHOES_LIVE_EXIT_IP=<the server's public address> \
cargo test --locked --test live_socks -- --nocapture
```

The config is an `examples/*_client.yaml` shape: a `socks` listener at
`SHOES_LIVE_SOCKS` with the outbound under test in its chain. Generate it
from the server's own client profile with a script that writes an
owner-only file and never prints a value. Run it once more with the
password changed by one character: every check must fail, or the run proved
nothing. Lifecycle checks the harness does not cover (a session visible on
the server, a hold through dead-peer probes, a server-side disconnect
followed by a rebuild, the session gone after a stop) are a shell loop
around the same config, `ssh` to the server and its own control tool.

## Reading the result

- A mismatched obfuscation password produces no error at all and looks
  exactly like an unreachable server.
- A REALITY client that lands on the decoy fails on the decoy's certificate;
  the server-side log (`below minimum`, `forwarding to dest`) says why.
- Write what was checked, against which version, into the spec or the
  changelog entry, in words: no addresses, no keys, no captures.

## After

- Delete the temporary directory.
- `git status` before committing. If anything under `examples/`, `tests/` or
  `docs/` changed during the session, read the diff for a credential or a
  host before staging it.
