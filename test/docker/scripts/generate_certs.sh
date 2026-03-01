#!/bin/bash
# Generate test certificates for QUIC distribution

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../certs"

mkdir -p "$CERT_DIR"

echo "Generating test certificates in $CERT_DIR..."

openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 -nodes \
    -subj '/CN=localhost' \
    2>/dev/null

chmod 644 "$CERT_DIR/cert.pem"
chmod 600 "$CERT_DIR/key.pem"

echo "Certificates generated:"
ls -la "$CERT_DIR/"

echo ""
echo "Certificate info:"
openssl x509 -in "$CERT_DIR/cert.pem" -text -noout | head -20
