# Plan: the TUN server honours its `dns:` config

Spec: `docs/superpowers/specs/2026-08-31-tun-dns-config-design.md`.
Branch `fix/tun-honours-dns-config`, one commit per step, full suite before
calling it done.

1. **Thread the resolver.**
   - `tun::run_tun_from_config(config, resolver, shutdown_rx, close_fd)`;
     delete the in-place `NativeResolver::new()`.
   - `tun::start_tun_server`: `_resolver` → used.
   - `control::run_prepared`: `dns_registry.get_for_tun(tun_config.dns.as_ref())`
     inside the `cfg(any(unix, windows))` TUN branch.
   - Tests: the mock-upstream end-to-end test (spec §Tests 1) plus the
     protector-counting test (spec §Tests 4).

2. **Validation.** In `config::validate`, after dns groups are expanded and
   TUN group refs resolved: walk each TUN-referenced group transitively
   through group-name `bootstrap_url`s; reject hostname-URL specs without a
   bootstrap. Unit tests both ways (TUN rejected, plain server accepted).

3. **Docs.** CONFIG.md TUN `dns:` section; CHANGELOG Unreleased entry naming
   the behaviour change for existing TUN `dns:` configs.

Gates per commit: `cargo test --lib`, plus `--features ffi,control-stats`
once at the end; fmt; clippy on touched files.
