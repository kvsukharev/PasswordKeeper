#!/usr/bin/env bash
# gen-certs.sh — generate self-signed TLS certificates for development.
# Usage: bash gen-certs.sh [output-dir]
# Output: server.key, server.crt, ca.key, ca.crt in the given directory.
set -euo pipefail

OUTDIR="${1:-.}"
mkdir -p "$OUTDIR"

# Generate CA key and certificate
openssl genrsa -out "$OUTDIR/ca.key" 4096
openssl req -new -x509 -key "$OUTDIR/ca.key" \
    -out "$OUTDIR/ca.crt" \
    -days 3650 \
    -subj "/CN=PasswordKeeper Dev CA"

# Generate server key and CSR
openssl genrsa -out "$OUTDIR/server.key" 4096
openssl req -new -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "/CN=localhost"

# Sign the server certificate with the CA
openssl x509 -req \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/server.crt" \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

rm -f "$OUTDIR/server.csr"
chmod 600 "$OUTDIR"/*.key
echo "Certificates written to $OUTDIR"
