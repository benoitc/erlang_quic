# Quiche benchmark server for QUIC comparison
FROM rust:1.86-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl g++ linux-headers

WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

# Runtime image
FROM alpine:latest

RUN apk add --no-cache ca-certificates netcat-openbsd

COPY --from=builder /build/target/release/quiche-bench-server /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4435/udp

ENTRYPOINT ["/usr/local/bin/quiche-bench-server"]
CMD ["--listen", "0.0.0.0:4435", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
