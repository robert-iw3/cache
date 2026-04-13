#!/bin/bash
set -e

echo "[CERTS] Generating self-signed certificates for central server (valid 365 days)..."

mkdir -p certs

# Generate private key + self-signed cert (for central HTTPS on 443)
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/C=US/ST=TN/L=SMNTS/O=C2Hunter/CN=central.c2hunter.local" \
  -addext "subjectAltName = DNS:central.c2hunter.local,DNS:localhost,IP:127.0.0.1"

# Copy cert as CA bundle for agents (validation)
cp certs/cert.pem certs/ca.crt

chmod 600 certs/key.pem
chmod 644 certs/cert.pem certs/ca.crt

echo "✅ Certificates generated in ./certs/"
echo "   • certs/cert.pem  (server cert)"
echo "   • certs/key.pem   (server key)"
echo "   • certs/ca.crt    (for agent verification)"
echo ""
echo "Next steps:"
echo "   docker compose -f docker-compose-central.yaml up -d"
echo "   # Agents will mount ./certs/ca.crt and use https://YOUR_CENTRAL_IP:443"