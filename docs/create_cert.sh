#!/usr/bin/env bash
# create_cert.sh - self-signed certificate for the built-in web server
#
# Only needed when run_webapp.py serves HTTPS itself (SSL_ENABLED = True).
# Behind an Apache reverse proxy, Apache terminates TLS and this is not used.
#
# Usage (run from the project root, not from docs/):
#   bash docs/create_cert.sh [hostname]
#
# Writes certs/zsazsa.crt and certs/zsazsa.key, the paths SSL_CERT and SSL_KEY
# point at by default. Defaults to this host's name when no hostname is given.

set -euo pipefail

CERT_HOSTNAME="${1:-$(hostname -f 2>/dev/null || hostname)}"
CERT_DIR="certs"
CERT_FILE="$CERT_DIR/zsazsa.crt"
KEY_FILE="$CERT_DIR/zsazsa.key"
DAYS=825   # the longest validity browsers still accept

if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl not found. Install it and re-run."
    exit 1
fi

if [[ -f "$CERT_FILE" || -f "$KEY_FILE" ]]; then
    echo "ERROR: $CERT_FILE or $KEY_FILE already exists."
    echo "Remove both to replace the certificate."
    exit 1
fi

mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:4096 -nodes -days "$DAYS" \
    -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -subj "/CN=$CERT_HOSTNAME" -addext "subjectAltName=DNS:$CERT_HOSTNAME"

chmod 600 "$KEY_FILE"

echo ""
echo "Created $CERT_FILE and $KEY_FILE for $CERT_HOSTNAME, valid $DAYS days."
echo "Set SSL_ENABLED = True in config/__init__.py to use it."
