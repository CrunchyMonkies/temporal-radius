#!/bin/sh
# Generates a throwaway RadSec CA, server certificate and one NAS client certificate that every
# simulated NAS shares (NASes are told apart by NAS-Identifier, not by certificate).
#   ./gen-certs.sh [server-name]
# Output goes to ./certs/{server,nas}/{tls.crt,tls.key,ca.crt}. Never use these in production.
set -eu

SERVER_NAME=${1:-freeradius}
cd "$(dirname "$0")"
rm -rf certs && mkdir -p certs/server certs/nas
cd certs

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=RadSec Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca.key -out ca.crt 2>/dev/null

issue() { # dir cn extendedKeyUsage san
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
    "$3" "$4" > "$1/ext.cnf"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$1/tls.key" -out "$1/tls.csr" 2>/dev/null
  openssl x509 -req -in "$1/tls.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
    -extfile "$1/ext.cnf" -out "$1/tls.crt" 2>/dev/null
  cp ca.crt "$1/ca.crt"
  rm "$1/tls.csr" "$1/ext.cnf"
}

issue server "$SERVER_NAME" serverAuth "DNS:$SERVER_NAME"
# Shared by every NAS; its CN plays no part in CoA routing.
issue nas radsec-nas clientAuth "DNS:radsec-nas"

# FreeRADIUS runs as uid 101 in the container; keys must be readable by it.
chmod 644 */*
rm -f ca.srl
echo "certs written to $(pwd)"
