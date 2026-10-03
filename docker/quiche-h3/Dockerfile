# quiche HTTP/3 peer for GOAWAY interop testing (server and client)
# Debian rather than Alpine: quiche's BoringSSL bindings run bindgen, which
# dlopens libclang, and musl build scripts are statically linked.
FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make perl g++ git clang libclang-dev pkg-config

WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY --from=builder /build/target/release/quiche-h3-server /usr/local/bin/
COPY --from=builder /build/target/release/quiche-h3-client /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4441/udp

ENTRYPOINT ["/usr/local/bin/quiche-h3-server"]
CMD ["--listen", "0.0.0.0:4441", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
