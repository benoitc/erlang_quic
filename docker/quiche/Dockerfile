# Quiche benchmark server for QUIC comparison
# Debian rather than Alpine: quiche's BoringSSL bindings run bindgen, which
# dlopens libclang, and musl build scripts are statically linked.
FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make perl g++ git clang libclang-dev pkg-config

WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd

COPY --from=builder /build/target/release/quiche-bench-server /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4435/udp

ENTRYPOINT ["/usr/local/bin/quiche-bench-server"]
CMD ["--listen", "0.0.0.0:4435", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
