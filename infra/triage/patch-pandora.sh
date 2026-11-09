#!/usr/bin/env bash
# patch-pandora.sh - lokale Anpassungen am Pandora-Checkout, nach jedem git pull erneut ausfuehren.
#   1. bin/start_website.py: Gunicorn 2 Worker statt 10 (jeder Pandora-Prozess traegt ~500 MB Importe)
#   2. pandora/workers/*.yml: replicas 1 (ab Werk 51 Instanzen), Worker ohne Nutzen fuer Phishing-Triage aus
#      (externe Sandboxes ohne API-Key, Malware-Repos, grosse YARA-Pakete, QR-Codes)
#   3. config/generic.json: storage_db_hostname "kvrocks" (Compose-Servicename statt 127.0.0.1)
#   4. docker-compose.yml: restart-Policy, host.docker.internal (Lookyloo-Worker), start_website.py als Volume
#   5. optional LOOKYLOO_URL=https://... : apiurl des Lookyloo-Workers (auch Link-Basis im Bericht)
#   6. storage/ und indexing/ gehoeren rekursiv uid 999 (Kvrocks im Container), sonst "Permission denied"
#      und Kvrocks haengt in einer Restart-Schleife, Pandora meldet dann endlos "Waiting on storage to start"
# Idempotent: jede Aenderung prueft vorher, ob sie noch noetig ist. Konfig-Samples werden kopiert, falls sie fehlen.
set -euo pipefail
cd "$(dirname "$0")"

DISABLE=(comodo hybridanalysis joesandbox mwdb malwarebazaar yarahq_full yarahub qrcode)
# Lookyloo-URL fuer den Worker: Pandora baut daraus auch die Links im Bericht, also den Namen nehmen,
# den der Browser erreicht (zu Hause https://lookyloo.provinglab.de/). Leer = nicht anfassen.
LOOKYLOO_URL="${LOOKYLOO_URL:-}"

echo "== Konfig-Samples"
[[ -f config/generic.json ]] || cp config/generic.json.sample config/generic.json
[[ -f config/logging.json ]] || cp config/logging.json.sample config/logging.json
for f in pandora/workers/*.yml.sample; do [[ -f "${f%.sample}" ]] || cp "$f" "${f%.sample}"; done

echo "== bin/start_website.py"
if grep -q "'gunicorn', '-w', '2'," bin/start_website.py; then echo "   schon erledigt"; else
    python3 -c "p='bin/start_website.py'; s=open(p).read(); a=\"'gunicorn', '-w', '10',\"; assert s.count(a)==1; open(p,'w').write(s.replace(a, \"'gunicorn', '-w', '2',\"))"
    echo "   Gunicorn-Worker 10 -> 2"
fi

echo "== Worker"
python3 - "${DISABLE[@]}" <<'PYEOF'
import glob, re, sys
disable = set(sys.argv[1:]); changed = 0
for p in sorted(glob.glob("pandora/workers/*.yml")):
    s = open(p).read(); o = s
    s = re.sub(r"^(\s*replicas:\s*)\d+", r"\g<1>1", s, flags=re.M)
    name = p.rsplit("/", 1)[1][:-4]
    if name in disable and "disabled: true" not in s:
        s = s.replace("settings:\n", "settings:\n  disabled: true\n", 1) if "settings:\n" in s else s + "\nsettings:\n  disabled: true\n"
    if s != o:
        open(p, "w").write(s); changed += 1
print(f"   {changed} Dateien geaendert, replicas=1 ueberall, aus: {' '.join(sorted(disable))}")
PYEOF

echo "== config/generic.json"
python3 - <<'PYEOF'
import json
p = "config/generic.json"; c = json.load(open(p))
if c.get("storage_db_hostname") == "kvrocks": print("   schon erledigt")
else:
    c["storage_db_hostname"] = "kvrocks"; json.dump(c, open(p, "w"), indent=4); print("   storage_db_hostname -> kvrocks")
PYEOF

echo "== docker-compose.yml"
python3 - <<'PYEOF'
import re
p = "docker-compose.yml"; s = open(p).read(); o = s
if "restart:" not in s:
    s = re.sub(r"^(  [a-z-]+:\n)", r"\1    restart: unless-stopped\n", s, flags=re.M)
if "extra_hosts" not in s:
    s = s.replace("    ports:\n        - 6100:6100", '    extra_hosts:\n        - "host.docker.internal:host-gateway"\n    ports:\n        - 6100:6100')
if "start_website.py" not in s:
    s = s.replace("        - ./tasks:/pandora/tasks\n", "        - ./tasks:/pandora/tasks\n        - ./bin/start_website.py:/pandora/bin/start_website.py\n")
open(p, "w").write(s); print("   compose:", "geaendert" if s != o else "schon erledigt")
PYEOF

if [[ -n "$LOOKYLOO_URL" ]]; then
    echo "== Lookyloo-Worker apiurl"
    if grep -q "^apiurl: $LOOKYLOO_URL\$" pandora/workers/lookyloo.yml; then echo "   schon $LOOKYLOO_URL"; else
        python3 -c "import re,sys; p='pandora/workers/lookyloo.yml'; s=open(p).read(); s,c=re.subn(r'^apiurl: .*$', 'apiurl: '+sys.argv[1], s, flags=re.M); assert c==1; open(p,'w').write(s)" "$LOOKYLOO_URL"
        echo "   apiurl -> $LOOKYLOO_URL"
    fi
fi

echo "== Verzeichnisrechte fuer Kvrocks (uid 999)"
# rekursiv pruefen: nach einem Neu-Checkout oder Kopieren kann db/ darunter wieder dem Benutzer gehoeren
for d in storage indexing; do
    if [[ -z "$(find "$d" ! -uid 999 -print -quit)" ]]; then echo "   $d: schon 999"; else sudo chown -R 999:999 "$d"; echo "   $d -> 999:999"; fi
done
echo "fertig. jetzt: Konfig (MISP, Lookyloo-Worker), docker compose build && docker compose up -d"
