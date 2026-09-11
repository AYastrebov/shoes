# shoes on Keenetic routers: build and size against awg-manager's sing-box

2026-09-11. Two cross-builds of shoes for the Entware architectures
awg-manager ships for, measured against the sing-box fork it downloads at
run time. Sizes only: no router was available, so nothing here is RSS or
throughput. Both shoes binaries start under QEMU user emulation and pass
`version` and `check`.

## What awg-manager runs

awg-manager (`hoaxisr/awg-manager`) does not build sing-box itself. Its
installer pins a release of `hoaxisr/amnezia-box`, a fork of Amnezia's
sing-box fork, and downloads the binary for the router's Entware
architecture (`internal/singbox/installer/embedded.go`). Pinned at the time
of writing: `1.14.0-awgm.16`, built with
`with_gvisor,with_quic,with_wireguard,with_utls,with_acme,with_clash_api,
with_v2ray_api,with_naive_outbound,with_cloudflared,with_musl,with_awg,
with_low_memory`, CGO on with a musl toolchain for the two architectures
below, `-ldflags "-s -w"`, `GOMIPS=softfloat` for MIPS.

## Results

Static, stripped ELF executables in every row. shoes rows are the `mobile`
branch at a85cda6 plus the changes in "What it took", features `clash-api`.

| Binary | aarch64-3.10 | mipsel-3.4 |
|---|---:|---:|
| sing-box 1.14.0-awgm.16 (as shipped) | 61,430,072 | 74,285,180 |
| shoes, `release` (opt-level 3, fat LTO) | 14,014,792 | 17,097,188 |
| shoes, `release-mobile` (opt-level s, panic abort) | 8,083,776 | 10,064,412 |

Ratios against the shipped sing-box: shoes `release` is 4.4x smaller on
aarch64 and 4.3x smaller on mipsel; `release-mobile` is 7.6x and 7.4x
smaller.

Feature sets are not identical -- sing-box carries gVisor, ACME, the V2Ray
API, cloudflared and a naive outbound that shoes does not -- so this is the
size of what each ships, not of matched functionality. awg-manager's own
installer notes the cost of the sing-box binary on the slowest router:
hashing "~80MB" takes about 13 s of CPU on soft-float MIPS.

## What it took

The aarch64 build needed nothing beyond cross-rs. The mipsel build needed
seven things, each recorded in the tree so `scripts/build-keenetic.sh`
reproduces it:

1. **cross-rs `main` images, not 0.2.5.** The older images' GCC segfaults
   compiling jemalloc, on both targets. (`Cross.toml`)
2. **No jemalloc on MIPS.** Even the newer MIPS GCC crashes on it, jemalloc
   has no background-thread support for the target, and a 32-bit soft-float
   router with 128-256 MiB is the wrong place for its arenas anyway.
   (`Cargo.toml`, `src/main.rs`)
3. **`portable-atomic` for the 64-bit counters.** The target has no 64-bit
   atomics (`max-atomic-width` 32). Five files used `AtomicU64`; they take
   it from `util::AtomicU64` now, which is std's type on every target that
   has one and `portable_atomic`'s lock-backed fallback here. The crate is
   a dependency only on such targets.
4. **`build-std` on nightly.** `mipsel-unknown-linux-musl` is tier 3: no
   prebuilt std. Pinned to `nightly-2026-09-11` (rustc 1.100.0-nightly,
   67eda617e), and the cross images are pinned by digest, so the script
   reproduces these numbers rather than whatever the tags point at later.
   (`Cross.toml`, `scripts/build-keenetic.sh`)
5. **The toolchain's own C runtime files.** Rust's musl targets link the
   start files and `libunwind` that ship with the prebuilt std, which a
   `build-std` target lacks: `-C link-self-contained=no` for the start
   files, and GCC's `libgcc_eh` under the name `libunwind` for the
   unwinder, since it provides the same `_Unwind_*` interface.
   (`.cargo/config.toml`, `Cross.toml`)
6. **bindgen for aws-lc-sys.** No prebuilt bindings for MIPS, so the image
   gets clang and libclang. (`Cross.toml`)
7. **Unprefixed aws-lc symbols.** The prefixed bindings name every
   function with LLVM's verbatim-name marker (`\u{1}`), which the MIPS
   backend fails to strip, with or without LTO: the object then references
   symbols that begin with a control byte, and the link fails with 136
   undefined references while the linker's own trace shows the definitions
   present. `AWS_LC_SYS_NO_PREFIX=1` builds and binds the library without
   the prefix and therefore without the marker. Nothing else in the binary
   uses those names (ring has its own prefix). This is an LLVM bug worth
   reporting upstream with a reduced case. (`Cross.toml`)

Two things happen without a fix. The nightly MIPS backend crashes about one
full build in two (a SIGSEGV in LLVM's scheduler, in whichever crate is
compiling at the time); a resumed build keeps what compiled, so the build
script retries. And the `pre-build` apt step in the cross image needs
`DEBIAN_FRONTEND=noninteractive`, or tzdata's prompt blocks it silently.

The ABI matches Keenetic's: Rust's mipsel musl target is mips32r2, o32,
soft-float, which is what Entware's mipsel-3.4 toolchain produces.

## What is not measured

- Memory and throughput on a router. The sing-box fork ships with
  `with_low_memory`; shoes has the `network-extension` sizing for
  constrained hosts, not yet tried on a router. Both need a real Keenetic.
- The `mips-3.4` (big-endian) architecture, which awg-manager also ships.
  Rust has `mips-unknown-linux-musl` (tier 3, same route as mipsel); not
  attempted.
- Whether the lock-backed 64-bit atomics cost anything measurable on the
  counting path. They are per-connection counters written once per read or
  write; on a 1004Kc at router throughput this is unlikely to show, but it
  is unmeasured.
