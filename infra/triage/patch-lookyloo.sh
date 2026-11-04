#!/usr/bin/env bash
# patch-lookyloo.sh - lokale Anpassungen am Lookyloo-Checkout, nach jedem git pull erneut ausfuehren.
#   1. Dockerfile: Basis ubuntu:24.04 (Projekt verlangt Python >= 3.11; 22.04 hat 3.10),
#      libasound2 -> libasound2t64 (Noble-Umbenennung), pip mit --break-system-packages (PEP 668),
#      Playwright nur mit Chromium (spart WebKit/Firefox, halber Build)
#   2. bin/start_website.py: Gunicorn 2 Worker statt 10 (je Worker ~370 MB)
#   3. docker-compose.yml: restart-Policy, host.docker.internal (Tor-Proxy), start_website.py als Volume
# Idempotent: jede Ersetzung prueft vorher, ob sie noch noetig ist.
set -euo pipefail
cd "$(dirname "$0")"

rep() {  # rep DATEI ALT NEU : ersetzt genau einmal, meldet, wenn schon erledigt
    if grep -qF -- "$3" "$1"; then echo "   $1: schon erledigt ($3)"; return; fi
    n=$(grep -cF -- "$2" "$1" || true)
    [[ "$n" == 1 ]] || { echo "FEHLER $1: '$2' ${n}x gefunden"; exit 1; }
    python3 - "$1" "$2" "$3" <<'PYEOF'
import sys; p, old, new = sys.argv[1:]
s = open(p).read(); open(p, "w").write(s.replace(old, new, 1))
PYEOF
    echo "   $1: $2 -> $3"
}

echo "== Dockerfile"
rep Dockerfile "FROM ubuntu:22.04" "FROM ubuntu:24.04"
rep Dockerfile "libasound2 " "libasound2t64 "
rep Dockerfile "pip3 install poetry" "pip3 install --break-system-packages poetry"
# pysocks: requests braucht es fuer socks5-Proxys (Knoten-Ansicht, Lookups); im 24.04-Image nicht dabei
if grep -q "pip install pysocks" Dockerfile; then
    echo "   Dockerfile: pysocks schon drin"
else
    python3 -c 'p="Dockerfile"; s=open(p).read(); assert s.count("RUN poetry install\n")==1; open(p,"w").write(s.replace("RUN poetry install\n","RUN poetry install\nRUN poetry run pip install pysocks\n",1))'
    echo "   Dockerfile: pysocks nach poetry install eingefuegt"
fi
# PlaywrightCapture-Bug: get_local_hostnames() zerlegt /etc/hosts an einem Leerzeichen, Docker >= 29 schreibt Tabs,
# jede Capture wird mit "weird URL" geblockt. Issue Lookyloo/PlaywrightCapture#267; Zeile raus, sobald der Fix released ist:
if grep -q "playwrightcapture/helpers.py" Dockerfile; then
    echo "   Dockerfile: helpers.py-Fix schon drin"
else
    python3 -c 'p="Dockerfile"; s=open(p).read(); a="RUN poetry run pip install pysocks\n"; assert s.count(a)==1; open(p,"w").write(s.replace(a, a+"RUN sed -i \"s/line.split('"'"' '"'"', 1)/line.split(None, 1)/\" $(find /root/.cache/pypoetry -path \"*playwrightcapture/helpers.py\")\n",1))'
    echo "   Dockerfile: helpers.py-Fix nach pysocks eingefuegt"
fi
if grep -q "playwright install" Dockerfile && ! grep -q "playwright install.*chromium" Dockerfile; then
    python3 -c 'import re; p="Dockerfile"; s=open(p).read(); s=re.sub(r"(playwright install[^\n&;]*)", r"\1 chromium", s, count=1); open(p,"w").write(s)'
    echo "   Dockerfile: playwright install -> nur chromium:"; grep -n "playwright install" Dockerfile
else
    echo "   Dockerfile: playwright nur chromium schon erledigt"
fi

echo "== bin/start_website.py"
rep bin/start_website.py "'gunicorn', '-w', '10'," "'gunicorn', '-w', '2',"

echo "== docker-compose.yml"
python3 - <<'PYEOF'
import re
p = "docker-compose.yml"; s = open(p).read(); o = s
s = s.replace("version: '3'\n", "")
if "restart:" not in s:
    s = re.sub(r"^(  [a-z-]+:\n)", r"\1    restart: unless-stopped\n", s, flags=re.M)
if "extra_hosts" not in s:
    s = s.replace('    ports:\n        - "5100:5100"', '    extra_hosts:\n        - "host.docker.internal:host-gateway"\n    ports:\n        - "5100:5100"')
if "start_website.py" not in s:
    s = s.replace("        - ./logs_web:/lookyloo/website/logs\n",
                  "        - ./logs_web:/lookyloo/website/logs\n        - ./bin/start_website.py:/lookyloo/bin/start_website.py\n")
open(p, "w").write(s); print("   compose:", "geaendert" if s != o else "schon erledigt")
PYEOF
echo "fertig. jetzt: docker compose build && docker compose up -d"
