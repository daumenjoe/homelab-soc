# triage: Lookyloo + Pandora auf einer VM

Phishing-Triage ohne Detonation. **Lookyloo** rendert URLs in einem isolierten
Chromium über Tor: Redirect-Kette, nachgeladene Domains, Screenshot, Push nach
MISP. **Pandora** zerlegt Mails und Anhänge statisch: Extractor, OLE/DDE, PDF,
Observables, Hashlookup, MISP, ClamAV, YARA, Vorschau. Beides CIRCL, beides
`docker compose`. Arbeitsteilung: Pandora zerlegt, Lookyloo rendert; URLs aus
Mails gehen über den Observables-Reiter an Lookyloo, HTML-Anhänge per Knopf.
Befund 47 in TUNING.md erzählt, warum alles so ist, wie es hier steht.

## Dateien

| | |
|---|---|
| `build-triage-vm.sh` | legt die VM auf einem Proxmox-Host unbeaufsichtigt an (Cloud-Init-Userdata, erster Boot richtet Lookyloo komplett ein) |
| `patch-lookyloo.sh` | lokale Änderungen am Lookyloo-Checkout; idempotent, nach jedem `git pull` erneut ausführen; wird vom Build-Skript eingebettet |
| `patch-pandora.sh` | dasselbe für Pandora |

## Ressourcen, gemessen

| | Leerlauf | Bemerkung |
|---|---|---|
| Lookyloo | 2,1 GB | nach Gunicorn 10 → 2 Worker; ab Werk 4,5 GB. Capture +1 GB |
| Pandora | 3,5 GB | nach Replicas 1, acht Worker aus, Gunicorn 2; ab Werk 6,2 GB |
| ClamAV | 1,0 GB | Signaturen im Speicher |
| **VM** | **10 GB fest, kein Ballooning, 2 vCPU, CPU-Typ `host`** | mit Ballooning drückt Proxmox die VM ab 80 % Host-Auslastung aufs Minimum; `kvm64` hat kein SSE4.2, NumPy im Pandora-Image bricht beim Build ab; mehr Kerne heißen mehr Gunicorn-Worker |

Vorher prüfen, ob der Host das hergibt. Mit Bordmitteln, auf dem Proxmox:
RRD-Wochenmaximum je Gast (`pvesh get /nodes/<node>/qemu/<id>/rrddata
--timeframe week`) und, bei VMs, `qm guest exec <id> -- free -m`, weil der
RRD-Wert den Page-Cache des Gastes enthält. Bei uns belegten drei VMs mit
18 GB Zuteilung 7,7 GB; auf 13 verkleinert, 10 für triage frei.

## 1. VM anlegen

Voraussetzung auf dem Proxmox: Storage `local` mit Inhaltstyp „Snippets“
(Datacenter → Storage → local → Edit). Beide Skripte nach `/root/triage/`.

```bash
./build-triage-vm.sh --vmid 109 --ip 192.168.178.232/24 --gw 192.168.178.1 --dns 192.168.178.251 \
    --sshkey /root/triage-key.pub --misp-url https://misp.provinglab.de --misp-key-file /root/misp.txt \
    --apt-proxy http://192.168.178.230:3142
```

Optionen: `--name`, `--storage` (local-lvm), `--bridge` (vmbr0), `--cores` (2),
`--memory` (10240), `--user` (neo), `--sshkey DATEI` oder `--password-file DATEI`,
`--misp-url` + `--misp-key-file`, `--apt-proxy`, `--no-tor`. Die Key-Datei
enthält nur den eigenen Key, nicht die `authorized_keys` des Hosts.

Erster Boot 5 Minuten, Protokoll im Gast `/var/log/cloud-init-output.log`,
Ende `TRIAGE-SETUP-DONE`, danach `http://<ip>:5100`. Test: Capture von
`https://check.torproject.org`, der Screenshot sagt „Congratulations“.

Danach vom Proxmox löschen: Key- und Passwortdatei, `misp.txt` und das
Userdata unter `/var/lib/vz/snippets/` (enthält MISP-Key und Passwort-Hash).

## 2. Pandora dazu

Noch Handarbeit, bis der `--pandora`-Block im Build-Skript steht:

```bash
cd ~/stacks && git clone --depth 1 https://github.com/pandora-analysis/pandora.git && cd pandora
cp /pfad/patch-pandora.sh . && bash patch-pandora.sh
python3 - <<'PYEOF'
import json
key = open("/home/neo/misp.txt").read().strip(); assert key
c = json.load(open("config/generic.json"))
c["misp"].update(url="https://misp.provinglab.de", apikey=key, tls_verify=False)
json.dump(c, open("config/generic.json", "w"), indent=4)
def edit(p, pairs):
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (p, old); s = s.replace(old, new)
    open(p, "w").write(s)
edit("pandora/workers/lookyloo.yml", [("  apiurl: https://lookyloo.circl.lu/", "  apiurl: http://host.docker.internal:5100/")])
edit("pandora/workers/misp.yml", [("  apikey: null", f"  apikey: {key}"),
                                  ("  apiurl: https://misp.example.com", "  apiurl: https://misp.provinglab.de"),
                                  ("  tls_verify: true", "  tls_verify: false")])
PYEOF
chmod 600 config/generic.json pandora/workers/misp.yml && shred -u ~/misp.txt
docker compose build && docker compose up -d
```

Start dauert gut zwei Minuten (ClamAV lädt Signaturen, Pandora wartet 60 s,
LibreOffice startet). Dann `http://<ip>:6100`, eine PDF hochladen. Kontrolle:
`docker stats --no-stream`, beide Stacks zusammen unter 7 GB.

## 3. Zugangsschutz (wo nötig)

Lookyloo und Pandora haben keine Anmeldung. Außerhalb des Heimnetzes Nginx
mit Basic Auth und TLS davor, Container-Ports auf `127.0.0.1` binden:

```bash
sudo apt install -y nginx apache2-utils
sudo htpasswd -c /etc/nginx/triage.htpasswd analyst
sudo openssl req -x509 -nodes -days 1095 -newkey rsa:2048 -subj '/CN=triage' \
    -keyout /etc/ssl/private/triage.key -out /etc/ssl/certs/triage.crt
# server-Block: listen 443 ssl, auth_basic, proxy_pass http://127.0.0.1:5100 (Lookyloo) bzw. :6100 (Pandora)
# in beiden docker-compose.yml: "127.0.0.1:5100:5100" bzw. "127.0.0.1:6100:6100", dann docker compose up -d
```

## Betrieb

| | |
|---|---|
| Update | `git pull && bash patch-*.sh && docker compose build && docker compose up -d` im jeweiligen Stack |
| Logs | `docker compose logs --tail 50 lookyloo` / `… pandora` |
| Tor-Check | `curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip` |
| Speicher | `free -m`, `docker stats --no-stream` |
| DNS | die VM muss Phishing-Domains auflösen: Pi-hole-Gruppe ohne Blocking, Anfragen bleiben im FTL-Log |
| SIEM | Wazuh-Agent, `infra_hosts`-Eintrag („analysis sandbox, DNS lookups are deliberate“), Watchdog-Check auf beide Ports |

## Offen

- `--pandora`-Block und Nginx-Option im Build-Skript
- PlaywrightCapture #267: die `helpers.py`-Zeile in `patch-lookyloo.sh` entfällt, sobald der Fix released ist
- Pandora-Worker, der URLs aus den Observables an Lookyloo reicht (heute nur HTML-Anhänge)
- Aufbewahrung der Captures und Uploads festlegen; beides liegt unbegrenzt unter `~/stacks/*/`
