---
name: adding-a-config-option
description: Checklist for adding, renaming, bounding or removing a YAML configuration field in shoes, so the option is validated, documented in CONFIG.md, parsed by an example, and smoke-tested in CI. Use when a change touches src/config/, a config struct's fields, a default, a limit, or an example under examples/.
---

# Adding a config option

## 1. The type

- Fields live on the config structs in `src/config/types/` (clients in
  `client.rs`, servers in `server.rs`, transports in `transport.rs`, DNS in
  `dns.rs`). `protocol:` blocks are `deny_unknown_fields`, so a misspelled
  field is refused when the config loads; keep that.
- Use `NoneOrOne<T>` / `NoneOrSome<T>` / `OneOrSome<T>` (`src/option_util.rs`)
  for optional and list-valued fields, following the neighbouring field.
- A secret goes in `Redacted<T>` (`src/config/types/redacted.rs`), so `Debug`
  cannot print it.
- Follow the reference's name where one exists (`udp_timeout` is sing-box's,
  `min_idle_session` is sing-box's, `max_early_data` is sing-box's), and say
  so in `CONFIG.md`.
- `src/config/types/mod.rs` re-exports the types; follow the pattern.

## 2. Validation, in `src/config/validate.rs`

- Refuse loudly rather than ignoring: an option that is accepted but not
  implemented is rejected with a message that says so.
- Validate what the reference validates, with the source named in the
  message or a comment: bounds, minimum lengths, chain position
  (`TerminalConnector` outbounds are refused mid-chain).
- A refusal must not repeat the presented value when the field is a
  credential; test with `assert!(!err.contains(secret))`.
- Add a validation test next to the existing ones in the same file, with a
  config that loads and one that is refused.

## 3. Documentation and examples

- `CONFIG.md`: the field in the YAML block of its section, with its default,
  and a sentence on what it does and when a user needs it. Say the things a
  user would otherwise learn painfully.
- `examples/`: a config that parses and uses the field. Check it:

  ```bash
  cargo build --locked --bin shoes && target/debug/shoes --dry-run examples/<name>.yaml
  ```

  An example that references a PEM file the repository does not carry can
  be dry-run with a throwaway certificate outside the tree.
- `.github/workflows/test.yml`, the `Smoke test the examples` loop, and
  `.github/workflows/build.yml`, the `Smoke test binary` loop: add the
  example to both if it needs no certificate, so every PR's debug binary
  and every release binary parse it end to end.
- `CHANGELOG.md` under `## Unreleased`: the option, its default, and the
  reference it follows.

## 4. The factory

Where the field is consumed (`src/tcp/tcp_client_handler_factory.rs`,
`src/tcp/tcp_server_handler_factory.rs`, the protocol's own module), an
invariant that validation established is an `expect("validated when loading
config")`, not an `unwrap`.
