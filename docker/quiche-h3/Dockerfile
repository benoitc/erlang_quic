# quiche HTTP/3 peer for GOAWAY interop testing (server and client)
FROM rust:1.86-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl g++ linux-headers

WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/quiche-h3-server /usr/local/bin/
COPY --from=builder /build/target/release/quiche-h3-client /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4441/udp

ENTRYPOINT ["/usr/local/bin/quiche-h3-server"]
CMD ["--listen", "0.0.0.0:4441", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
