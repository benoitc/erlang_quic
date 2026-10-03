# quic-go HTTP/3 peer for GOAWAY interop testing (server and client)
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod ./
COPY main.go ./

RUN go mod tidy && go build -o goaway-h3 .

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/goaway-h3 /usr/local/bin/

RUN mkdir -p /certs

WORKDIR /app

EXPOSE 4440/udp

ENTRYPOINT ["/usr/local/bin/goaway-h3"]
CMD ["server", "--listen", "0.0.0.0:4440", "--cert", "/certs/cert.pem", "--key", "/certs/priv.key"]
