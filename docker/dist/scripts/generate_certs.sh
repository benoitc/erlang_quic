#!/bin/bash
# Generate self-signed certificates for QUIC distribution testing
set -e

CERT_DIR="${1:-../certs}"

mkdir -p "$CERT_DIR"

echo "Generating certificates in $CERT_DIR..."

# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/key.pem"

# Generate self-signed certificate (valid for all node hostnames)
openssl req -new -x509 -sha256 \
    -key "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/CN=quic-dist-test" \
    -addext "subjectAltName=DNS:node1,DNS:node2,DNS:node3,DNS:node4,DNS:node5,DNS:localhost,IP:172.30.1.1,IP:172.30.1.2,IP:172.30.1.3,IP:172.30.1.4,IP:172.30.1.5,IP:127.0.0.1"

echo "Certificates generated:"
echo "  - $CERT_DIR/cert.pem"
echo "  - $CERT_DIR/key.pem"

# Set permissions
chmod 644 "$CERT_DIR/cert.pem"
chmod 600 "$CERT_DIR/key.pem"

echo "Done."
