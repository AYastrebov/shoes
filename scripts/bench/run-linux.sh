#!/bin/bash
# Build shoes for Linux in a container and run the benchmarks there.
#
#   scripts/bench/run-linux.sh build            # release build into a volume
#   scripts/bench/run-linux.sh tunnels [env..]  # tunnels.py
#   scripts/bench/run-linux.sh tun [env..]      # tun_linux.py (real TUN device)
#   scripts/bench/run-linux.sh sh               # a shell in the bench container
#
# Extra arguments are VAR=value pairs passed to the script, e.g.
#   scripts/bench/run-linux.sh tunnels MODES=P ONLY=wg
#
# Linux is where the numbers mean something: the kernel TUN device, UDP
# segmentation offload and receive coalescing only exist there, and a macOS
# host with another VPN's network extension active distorts UDP badly.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=shoes-bench
VOLS=(-v shoes-bench-target:/target -v shoes-bench-cargo:/usr/local/cargo/registry -v shoes-bench-git:/usr/local/cargo/git)
cmd=${1:-}; shift || true
envs=(); for kv in "$@"; do envs+=(-e "$kv"); done

case "$cmd" in
  build)
    docker run --rm -v "$REPO":/src:ro "${VOLS[@]}" -w /src ${envs[@]+"${envs[@]}"} rust:1-bookworm \
      bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq cmake clang >/dev/null 2>&1; cargo build --release --locked --target-dir /target 2>&1 | tail -3'
    ;;
  tunnels|tun|sh)
    docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE "$REPO/scripts/bench" >/dev/null
    run='mkdir -p /dev/net; [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200; export SHOES=${SHOES:-/target/release/shoes};'
    case "$cmd" in
      tunnels) run+=' python3 /bench/tunnels.py' ;;
      tun)     run+=' echo -1 > /proc/sys/kernel/perf_event_paranoid; echo 0 > /proc/sys/kernel/kptr_restrict; python3 /bench/tun_linux.py' ;;
      sh)      run+=' exec bash' ;;
    esac
    tty=(); [ "$cmd" = sh ] && tty=(-it)
    docker run --rm --privileged ${tty[@]+"${tty[@]}"} -v "$REPO/scripts/bench":/bench:ro -v shoes-bench-target:/target:ro ${envs[@]+"${envs[@]}"} $IMAGE bash -c "$run"
    ;;
  *) sed -n 2,14p "$0"; exit 2 ;;
esac
