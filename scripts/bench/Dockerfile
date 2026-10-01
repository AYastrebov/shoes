FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq python3 iproute2 iperf3 curl ca-certificates procps ethtool openssl gawk linux-perf >/dev/null && \
    curl -sL https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-arm64.tar.gz | tar xz -C /opt && \
    ln -s /opt/sing-box-1.14.2-linux-arm64/sing-box /usr/local/bin/sing-box && sing-box version | head -1
