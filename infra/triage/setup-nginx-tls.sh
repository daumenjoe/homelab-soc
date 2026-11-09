#!/usr/bin/env bash
# setup-nginx-tls.sh - nginx mit TLS vor Lookyloo und Pandora auf der Triage-VM.
#   ohne --names:  Lookyloo :443, Pandora :8443, selbst signiertes Zertifikat (falls keins liegt)
#   mit  --names:  beide auf :443, getrennt per SNI (server_name); Zertifikat kommt vom Relay
#                  (acme.sh, /root/deploy/triage.sh schreibt /etc/ssl/certs/triage.crt + private/triage.key)
#
# Grund (Befund 48): Uploads an Pandora und Captures in Lookyloo transportieren absichtlich
# Schadmaterial. Ueber Klartext-HTTP sieht der Suricata-Sensor den Inhalt und meldet ihn.
# Mit TLS sieht er nur noch Metadaten. Die Container-Ports 5100/6100 werden danach nur noch
# auf 127.0.0.1 gebunden, der Weg fuehrt ausschliesslich ueber nginx.
#
#   sudo ./setup-nginx-tls.sh                       # TLS, ohne Anmeldung (zu Hause)
#   sudo ./setup-nginx-tls.sh --htpasswd DATEI      # zusaetzlich Basic Auth (Arbeit); DATEI im htpasswd-Format
#   sudo ./setup-nginx-tls.sh --no-pandora          # nur Lookyloo
#   sudo ./setup-nginx-tls.sh --names lookyloo.provinglab.de pandora.provinglab.de   # SNI auf 443
#
# Idempotent: Zertifikat nur, wenn keins da ist; Konfig wird ueberschrieben (ist generiert);
# Compose-Dateien nur geaendert, wenn die Ports noch offen gebunden sind.
# Kein 2>/dev/null: wenn etwas schiefgeht, soll es sichtbar sein.
set -euo pipefail

HTPASSWD=""; PANDORA=1; LNAME=""; PNAME=""
STACKS="${STACKS:-/home/neo/stacks}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --htpasswd) HTPASSWD="$2"; shift ;;
        --no-pandora) PANDORA=0 ;;
        --names) LNAME="$2"; shift; if [[ -n "${2:-}" && "${2:-}" != --* ]]; then PNAME="$2"; shift; fi ;;
        -h|--help) sed -n '2,18p' "$0"; exit 1 ;;
        *) echo "unbekannte Option: $1"; exit 1 ;;
    esac
    shift
done
[[ $EUID -eq 0 ]] || { echo "als root ausfuehren"; exit 1; }
[[ -z "$HTPASSWD" || -f "$HTPASSWD" ]] || { echo "htpasswd-Datei fehlt: $HTPASSWD"; exit 1; }
[[ -d "$STACKS/lookyloo" ]] || { echo "kein Lookyloo-Checkout unter $STACKS (STACKS= setzen)"; exit 1; }
[[ -z "$LNAME" || $PANDORA -eq 0 || -n "$PNAME" ]] || { echo "--names braucht zwei Namen (Lookyloo, Pandora) oder --no-pandora"; exit 1; }

echo "== nginx"
if ! command -v nginx >/dev/null; then
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
else
    echo "   installiert"
fi
rm -f /etc/nginx/sites-enabled/default

echo "== Zertifikat"
if [[ -f /etc/ssl/certs/triage.crt && -f /etc/ssl/private/triage.key ]]; then
    echo "   vorhanden: $(openssl x509 -in /etc/ssl/certs/triage.crt -noout -enddate)"
else
    IP="$(hostname -I | awk '{print $1}')"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1825 \
        -keyout /etc/ssl/private/triage.key -out /etc/ssl/certs/triage.crt \
        -subj "/CN=$(hostname)" -addext "subjectAltName=DNS:$(hostname),IP:$IP"
    chmod 600 /etc/ssl/private/triage.key
    echo "   selbst signiert fuer $(hostname) / $IP, 5 Jahre"
fi

AUTH=""
if [[ -n "$HTPASSWD" ]]; then
    install -m 0640 -o root -g www-data "$HTPASSWD" /etc/nginx/triage.htpasswd
    AUTH=$'    auth_basic           "Triage";\n    auth_basic_user_file /etc/nginx/triage.htpasswd;\n'
    echo "== Basic Auth aktiv ($(wc -l < /etc/nginx/triage.htpasswd) Benutzer)"
else
    echo "== ohne Basic Auth"
fi

site() {  # name port upstream_port max_body server_name
    cat > "/etc/nginx/sites-available/$1" <<NGX
# generiert von setup-nginx-tls.sh, Aenderungen dort
server {
    listen $2 ssl;
    server_name ${5:-_};

    ssl_certificate     /etc/ssl/certs/triage.crt;
    ssl_certificate_key /etc/ssl/private/triage.key;

${AUTH}    client_max_body_size $4;

    location / {
        proxy_pass         http://127.0.0.1:$3;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 300;
    }
}
NGX
    ln -sf "/etc/nginx/sites-available/$1" "/etc/nginx/sites-enabled/$1"
    echo "   $1: ${5:-*}:$2 -> 127.0.0.1:$3"
}
echo "== Sites"
if [[ -n "$LNAME" ]]; then
    # Zertifikat muss die Namen tragen, sonst Warnung im Browser; nur Hinweis, kein Abbruch
    openssl x509 -in /etc/ssl/certs/triage.crt -noout -ext subjectAltName | grep -q "DNS:$LNAME" \
        || echo "   HINWEIS: Zertifikat enthaelt $LNAME nicht; auf dem Relay /root/deploy/triage.sh laufen lassen"
    site lookyloo 443 5100 20m "$LNAME"
    if [[ $PANDORA -eq 1 ]]; then site pandora 443 6100 100m "$PNAME"; else rm -f /etc/nginx/sites-enabled/pandora; fi
else
    site lookyloo 443 5100 20m
    if [[ $PANDORA -eq 1 ]]; then site pandora 8443 6100 100m; else rm -f /etc/nginx/sites-enabled/pandora; fi
fi
nginx -t && systemctl enable --now nginx && systemctl reload nginx

echo "== Container-Ports nur noch lokal binden"
# Lookyloo zusaetzlich an die docker0-Adresse: der Pandora-Worker erreicht es ueber host.docker.internal
# (= docker0-Gateway), nicht ueber 127.0.0.1. Pandora selbst braucht niemand aus einem Container.
DOCKER0="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
echo "   docker0: $DOCKER0"
bind_local() {  # dir port [zusatz-ip]
    local f="$1/docker-compose.yml"
    [[ -f "$f" ]] || { echo "   $f fehlt, uebersprungen"; return; }
    if grep -qE "^\s*-\s*\"?127\.0\.0\.1:$2:$2\"?" "$f"; then echo "   $(basename "$1"): schon lokal"; return; fi
    python3 - "$f" "$2" "${3:-}" <<'PYEOF'
import re, sys
p, port, extra = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
m = re.search(rf'^(\s*-\s*)"?{port}:{port}"?\s*$', s, flags=re.M)
assert m, f"{p}: Port-Zeile {port}:{port} nicht gefunden"
ind = m.group(1)
lines = [f'{ind}"127.0.0.1:{port}:{port}"'] + ([f'{ind}"{extra}:{port}:{port}"'] if extra else [])
s = s[:m.start()] + "\n".join(lines) + s[m.end():]
open(p, "w").write(s); print(f"   {p}: {port} -> " + ", ".join(l.strip(' -"') for l in lines))
PYEOF
    (cd "$1" && docker compose up -d)
}
bind_local "$STACKS/lookyloo" 5100 "$DOCKER0"
[[ $PANDORA -eq 1 ]] && bind_local "$STACKS/pandora" 6100

echo
echo "fertig. Pruefen:"
if [[ -n "$LNAME" ]]; then
    echo "   curl -s -o /dev/null -w '%{http_code}\n' https://$LNAME/    -> 302 (ohne -k, wenn das Relay-Zertifikat liegt)"
    [[ $PANDORA -eq 1 ]] && echo "   curl -s -o /dev/null -w '%{http_code}\n' https://$PNAME/    -> 301"
else
    echo "   curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1/        -> 302 (oder 401 mit Basic Auth)"
    [[ $PANDORA -eq 1 ]] && echo "   curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/   -> 301 (oder 401)"
fi
echo "   curl -s -o /dev/null -w '%{http_code}\n' http://$(hostname -I | awk '{print $1}'):5100/   -> 000 (nicht mehr von aussen)"
echo "Pandora-Worker lookyloo.yml zeigt weiter auf http://host.docker.internal:5100/ (docker0, bleibt erreichbar)."
