# freespoof — multi-stage build producing a static (musl) binary in a minimal
# runtime image.
#
# IMPORTANT: freespoof uses raw sockets + a TUN device + NAT, so the container
# must be run with NET_ADMIN + NET_RAW, /dev/net/tun, and host networking (raw
# sockets need the host's real interface). See docker-compose.yml.
#
#   docker build -t freespoof -f deploy/Dockerfile .
#   docker run --rm --network host \
#       --cap-add=NET_ADMIN --cap-add=NET_RAW \
#       --device /dev/net/tun \
#       --sysctl net.ipv4.conf.all.rp_filter=0 \
#       -v $PWD/config:/etc/freespoof \
#       freespoof --config /etc/freespoof/server.toml

# ---- Builder: static musl release binary ----------------------------------
FROM rust:1-bookworm AS builder

ARG TARGET=x86_64-unknown-linux-musl
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools musl-dev clang cmake perl \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add ${TARGET}

WORKDIR /src
COPY . .

# Build all three binaries statically. aws-lc is avoided (ring backend), so a
# pure musl static build works without extra C deps beyond musl-tools.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target ${TARGET} \
 && mkdir -p /out \
 && cp target/${TARGET}/release/freespoof \
       target/${TARGET}/release/freespoof-client \
       target/${TARGET}/release/freespoof-server /out/

# ---- Runtime: minimal image with iproute2 + iptables ----------------------
FROM debian:bookworm-slim

# TUN setup + NAT need iproute2 and iptables at runtime; openssl for QUIC certs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/freespoof /out/freespoof-client /out/freespoof-server /usr/local/bin/
RUN mkdir -p /etc/freespoof

# No privilege drop inside the container by default; the caller grants exactly
# NET_ADMIN + NET_RAW. (freespoof auto-generates an ephemeral QUIC cert if none
# is configured.)
ENTRYPOINT ["/usr/local/bin/freespoof"]
CMD ["--config", "/etc/freespoof/config.toml"]
