#!/usr/bin/env bash
set -euo pipefail
D=/root/.acme.sh/misp.provinglab.de_ecc
H=neo@192.168.178.225
ssh "$H" "mkdir -p misp-docker/ssl"
scp -q "$D/fullchain.cer" "$H:misp-docker/ssl/cert.pem"
scp -q "$D/misp.provinglab.de.key" "$H:misp-docker/ssl/key.pem"
ssh "$H" "chmod 644 misp-docker/ssl/key.pem && cd misp-docker && docker compose restart misp-nginx 2>&1 | grep -v WARN" > /dev/null
echo "misp: cert deployed $(date +%F)"
