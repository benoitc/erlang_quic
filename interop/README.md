# QUIC Interop Runner Integration

This directory contains the integration for the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).

## Quick Start

### Build Docker Images

```bash
# Build client image
docker build -t erlang-quic-client -f interop/Dockerfile.client .

# Build server image
docker build -t erlang-quic-server -f interop/Dockerfile.server .
```

### Run Locally

```bash
# Run server
docker run -p 443:443/udp \
  -v $(pwd)/certs:/certs \
  -v $(pwd)/www:/www \
  -e TESTCASE=handshake \
  erlang-quic-server

# Run client
docker run \
  -e REQUESTS="https://host.docker.internal:443/test.txt" \
  -e TESTCASE=handshake \
  -e DOWNLOADS=/downloads \
  -v $(pwd)/downloads:/downloads \
  erlang-quic-client
```

## Supported Test Cases

All core test cases pass:

| Test Case | Client | Server | Notes |
|-----------|--------|--------|-------|
| `handshake` | ✓ | ✓ | Basic QUIC handshake |
| `transfer` | ✓ | ✓ | File download with flow control |
| `retry` | ✓ | ✓ | Retry packet handling |
| `keyupdate` | ✓ | ✓ | Key rotation during transfer |
| `chacha20` | ✓ | ✓ | ChaCha20-Poly1305 only |
| `multiconnect` | ✓ | ✓ | Multiple connections |
| `v2` | ✓ | ✓ | QUIC v2 support |
| `resumption` | ✓ | ✓ | Session resumption with PSK |
| `zerortt` | ✓ | ✓ | 0-RTT early data |
| `connectionmigration` | ✓ | ✓ | Active path migration |

## Integration with Official Runner

To add erlang-quic to the official interop runner:

1. Fork https://github.com/quic-interop/quic-interop-runner
2. Add entry to `implementations.json`:

```json
{
  "erlang-quic": {
    "name": "erlang-quic",
    "url": "https://github.com/benoitc/erlang_quic",
    "image": "erlang-quic"
  }
}
```

3. Push Docker images to a registry (e.g., Docker Hub, GitHub Container Registry)
4. Submit PR to the interop runner repository

## Environment Variables

### Client

- `REQUESTS` - Space-separated list of URLs to download
- `TESTCASE` - Test case name
- `DOWNLOADS` - Directory for downloaded files
- `SSLKEYLOGFILE` - Optional: Path for TLS key log

### Server

- `TESTCASE` - Test case name
- `PORT` - Listen port (default: 443)
- `CERTS` - Certificate directory (expects cert.pem, priv.key)
- `WWW` - Directory to serve files from
- `SSLKEYLOGFILE` - Optional: Path for TLS key log

## Exit Codes

- `0` - Success
- `1` - Failure
- `127` - Test case not supported

## Local Testing

Run the local compliance tests:

```bash
rebar3 ct --suite=quic_client_compliance_SUITE
```

Run interop tests against aioquic:

```bash
# Start aioquic server
docker compose -f docker/docker-compose.yml up -d

# Run tests
rebar3 ct --suite=quic_interop_SUITE
```
