FROM debian:bookworm-slim
# sing-box names its Linux releases by Debian's architecture names (amd64,
# arm64), so the image's own architecture picks the matching binary.
RUN apt-get update -qq && apt-get install -y -qq python3 iproute2 iperf3 curl ca-certificates procps ethtool openssl gawk linux-perf >/dev/null && \
    arch="$(dpkg --print-architecture)" && \
    curl -sL "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-${arch}.tar.gz" | tar xz -C /opt && \
    ln -s "/opt/sing-box-1.14.2-linux-${arch}/sing-box" /usr/local/bin/sing-box && sing-box version | head -1
