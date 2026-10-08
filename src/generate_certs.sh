#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AdaptiveQKE — certificate generation
# ---------------------------------------------------------------------------
# Creates a self-signed certificate + key for the TLS server.
# Output: certs/server.crt, certs/server.key
#
# RSA-2048: the project evaluates KEY EXCHANGE, and the certificate's
# signature algorithm doesn't affect the ML-KEM + ECDH hybrid group's
# performance, so a standard cert avoids confounding the comparison.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

mkdir -p "${CERT_DIR}"

if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
    echo "[certs] Certificate already exists at ${CERT_FILE}"
    echo "[certs] Delete it manually and re-run if you want to regenerate."
    exit 0
fi

echo "[certs] Generating RSA-2048 self-signed certificate"
echo "[certs]   key:  ${KEY_FILE}"
echo "[certs]   cert: ${CERT_FILE}"

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -keyout "${KEY_FILE}" \
    -out    "${CERT_FILE}" \
    -days   365 \
    -subj   "/C=PS/ST=Gaza/L=Gaza/O=AdaptiveQKE/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "${KEY_FILE}"
chmod 644 "${CERT_FILE}"

echo "[certs] Done."
