#!/bin/bash
# Generates self-signed SSL certificates for the v2.8 API Dashboard

mkdir -p certs
echo "[*] Generating 4096-bit RSA self-signed certificate..."

openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -sha256 -days 365 -nodes \
  -subj "/C=US/ST=Cyber/L=Grid/O=C2_Hunter/CN=localhost"

echo "[+] Success! Certificates generated in ./certs/"
echo "    key:  certs/key.pem"
echo "    cert: certs/cert.pem"