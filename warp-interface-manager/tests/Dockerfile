FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables wireguard-tools python3 curl jq procps util-linux shellcheck \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /project
