#!/usr/bin/env bash
# Issues a client certificate for one edge device. Its CN is the device id registered in the kit.
set -euo pipefail
[ $# -eq 1 ] && [[ "$1" =~ ^[A-Za-z0-9._:-]{1,64}$ ]] || { echo "usage: $0 <device-id>" >&2; exit 1; }
S="${SECRETS_DIR:-$(cd "$(dirname "$0")/.." && pwd)/secrets}/certs"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$S/device-$1.key" -out "$S/device-$1.csr"
openssl x509 -req -in "$S/device-$1.csr" -CA "$S/ca.crt" -CAkey "$S/ca.key" -CAcreateserial -days 825 \
  -extfile <(printf "extendedKeyUsage=clientAuth") -out "$S/device-$1.crt"
rm "$S/device-$1.csr"
echo "Issued $S/device-$1.crt and .key"
