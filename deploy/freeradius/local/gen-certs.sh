#!/bin/sh
# Generates a throwaway RadSec CA, server certificate and NAS client certificate for local testing.
#   ./gen-certs.sh [nas-identifier] [server-name]
# Output goes to ./certs/{server,nas,nas-02,nas-03}/{tls.crt,tls.key,ca.crt}; nas-02 / nas-03 are
# used by the keepalive tests in test.sh. Never use these certificates in production.
set -eu

NAS_ID=${1:-nas-01}
SERVER_NAME=${2:-freeradius}
cd "$(dirname "$0")"
rm -rf certs && mkdir -p certs/server certs/nas certs/nas-02 certs/nas-03
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
# The CN is the reverse-CoA key: it must equal the NAS-Identifier the worker puts in CoA requests.
issue nas "$NAS_ID" clientAuth "DNS:$NAS_ID"
issue nas-02 nas-02 clientAuth "DNS:nas-02"
issue nas-03 nas-03 clientAuth "DNS:nas-03"

# FreeRADIUS runs as uid 101 in the container; keys must be readable by it.
chmod 644 */*
rm -f ca.srl
echo "certs written to $(pwd) (NAS CN = $NAS_ID)"
