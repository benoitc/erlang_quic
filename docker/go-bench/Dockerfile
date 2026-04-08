# quic-go benchmark server for QUIC comparison
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod ./
COPY main.go ./

RUN go mod tidy && go build -o bench-server .

# Runtime image
FROM alpine:latest

RUN apk add --no-cache ca-certificates netcat-openbsd

COPY --from=builder /build/bench-server /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4434/udp

ENTRYPOINT ["/usr/local/bin/bench-server"]
CMD ["--listen", "0.0.0.0:4434", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
