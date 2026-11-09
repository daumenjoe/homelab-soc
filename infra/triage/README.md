# triage: Lookyloo + Pandora auf einer VM

Phishing-Triage ohne Detonation: Lookyloo rendert URLs in einem isolierten
Chromium (über Tor) und zeigt Redirect-Kette, nachgeladene Domains und
Screenshot; Pandora nimmt Mails und Anhänge statisch auseinander (Extractor,
OLE/DDE, PDF, Observables, Hashlookup, MISP, ClamAV, YARA, Vorschau). Beides
CIRCL, beides per `docker compose`, beides mit MISP-Anbindung.

Dieses Rezept ist das Ergebnis des ersten Aufbaus (TUNING Befund 47) und
läuft ohne die Stolpersteine von damals durch. Es ist bewusst so geschrieben,
dass es auf jeder Proxmox-Umgebung mit einer Debian-Cloud-VM funktioniert.

## 1. VM

Erfahrungswerte: Lookyloo braucht im Leerlauf ~3 GB (Gunicorn-Worker,
Indexer, Archiver), Pandora ab Werk ~6 GB (jeder Prozess trägt ~500 MB
Python-Importe; 51 Worker-Instanzen), abgespeckt ~3 GB. Chromium-Captures
brauchen kurz 1 GB extra. Darum:

- **8 GB RAM fest, kein Ballooning** (`--balloon 0`). Mit Ballooning drückt
  Proxmox die VM ab 80 % Host-Auslastung auf ihr Minimum, und beide Stacks
  thrashen im Swap.
- **2 vCPUs.** Gunicorn startet `Kerne × 2 + 1` Worker je Oberfläche; vier
  Kerne hießen neun Worker à 500 MB für einen Benutzer.
- **CPU-Typ `host`** (oder mindestens `x86-64-v2-AES`). Der Default `kvm64`
  hat kein SSE4.2; NumPy im Pandora-Image bricht beim Build mit
  „NumPy was built with baseline optimizations (X86_V2)“ ab.
- **64 GB Platte.** Zwei selbstgebaute Images (~12 GB) plus Build-Cache
  (~14 GB) plus System und Swap sind ~30 GB; mit 40 GB lief die Platte nach
  dem zweiten Build voll. Nachträglich: `qm resize <id> scsi0 +24G`, im
  Gast `growpart /dev/sda 1 && resize2fs /dev/sda1`.
- 2 GB Swap-Datei als Sicherheitsnetz, nicht als Arbeitsspeicher.

```bash
# auf pve, als root; ID, IP, Storage, Bridge anpassen
VMID=109; IP=192.168.178.232; GW=192.168.178.1; DNS=192.168.178.251
cd /var/lib/vz/template
curl -LO https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
qm create $VMID --name triage --ostype l26 --cpu host --cores 2 --memory 8192 --balloon 0 \
  --scsihw virtio-scsi-single --net0 virtio,bridge=vmbr0 --agent enabled=1 \
  --serial0 socket --vga serial0 --onboot 1
qm importdisk $VMID debian-13-genericcloud-amd64.qcow2 local-lvm
qm set $VMID --scsi0 local-lvm:vm-$VMID-disk-0,discard=on --boot order=scsi0
qm resize $VMID scsi0 +38G
# nur der eigene Key, nicht die ganze authorized_keys des Hosts
qm set $VMID --ide2 local-lvm:cloudinit --ipconfig0 ip=$IP/24,gw=$GW --nameserver $DNS \
  --ciuser neo --sshkeys /root/triage-key.pub
qm start $VMID
```

## 2. Grundausstattung im Gast

```bash
printf 'Acquire::http::Proxy "http://192.168.178.230:3142";\nAcquire::https::Proxy "DIRECT";\n' | sudo tee /etc/apt/apt.conf.d/01proxy
echo 'de_DE.UTF-8 UTF-8' | sudo tee -a /etc/locale.gen && sudo locale-gen
sudo apt update && sudo apt install -y docker.io docker-compose-v2 tor git qemu-guest-agent
sudo systemctl enable --now qemu-guest-agent
sudo usermod -aG docker "$USER"          # danach neu einloggen
printf '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "50m", "max-file": "3" }\n}\n' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker            # Log-Rotation gilt nur fuer danach erzeugte Container
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

Tor als SOCKS-Proxy für die Container. Aus einem Container ist `127.0.0.1`
der Container selbst, deshalb lauscht Tor auf allen Interfaces und lässt per
Policy nur Docker-Netze zu:

```bash
printf 'SocksPort 0.0.0.0:9050\nSocksPolicy accept 172.16.0.0/12\nSocksPolicy accept 127.0.0.1\nSocksPolicy reject *\n' | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor && sleep 5
curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip   # {"IsTor":true,...}
```

Umfeld: Pi-hole-Gruppe ohne Blocking für die VM-IP (sie muss Phishing-Domains
auflösen; die Anfragen bleiben im FTL-Log und damit im SIEM sichtbar), MISP-
Benutzer `triage` mit Rolle User und eigenem Auth-Key, Eintrag in
`infra_hosts` der Triage-Pipeline, Wazuh-Agent, Watchdog-Check auf beide
Web-UIs.

## 3. Lookyloo

```bash
mkdir -p ~/stacks && cd ~/stacks
git clone --depth 1 https://github.com/Lookyloo/lookyloo.git && cd lookyloo
for f in generic logging logging_web modules; do cp -n config/$f.json.sample config/$f.json; done
```

Compose: `version:`-Zeile raus, Restart-Policy, Host-Alias für Tor:

```bash
python3 - <<'EOF'
import re
p = "docker-compose.yml"; s = open(p).read()
s = s.replace("version: '3'\n", "")
s = re.sub(r"^(  [a-z-]+:\n)", r"\1    restart: unless-stopped\n", s, flags=re.M)
s = s.replace('    ports:\n        - "5100:5100"', '    extra_hosts:\n        - "host.docker.internal:host-gateway"\n    ports:\n        - "5100:5100"')
open(p, "w").write(s)
EOF
```

Konfig: alles über Tor; MISP in `modules.json` unter `MultipleMISPs` (nicht
`MISP`); Key aus einer Datei, nie aus dem Verlauf:

```bash
python3 - <<'EOF'
import json
c = json.load(open("config/generic.json"))
c["global_proxy"].update(enable=True, server="socks5://host.docker.internal:9050")
c["tor_proxy"]["server"] = "socks5://host.docker.internal:9050"
json.dump(c, open("config/generic.json", "w"), indent=2)
key = open("/home/neo/misp.txt").read().strip(); assert key
c = json.load(open("config/modules.json"))
c["MultipleMISPs"]["instances"]["MISP"].update(apikey=key, url="https://misp.provinglab.de",
    verify_tls_cert=False, enable_lookup=True, enable_push=True, default_tags=["source:lookyloo"])
json.dump(c, open("config/modules.json", "w"), indent=2)
EOF
chmod 600 config/modules.json
docker compose build && docker compose up -d
```

Test: `http://<ip>:5100`, Capture von `https://check.torproject.org`; der
Knoten trägt die Tor-Zwiebel, der Screenshot sagt „Congratulations“.

## 4. Pandora

```bash
cd ~/stacks && git clone --depth 1 https://github.com/pandora-analysis/pandora.git && cd pandora
cp -n config/generic.json.sample config/generic.json
cp -n config/logging.json.sample config/logging.json
for f in pandora/workers/*.yml.sample; do cp -n "$f" "${f%.sample}"; done
sudo chown -R 999:999 storage indexing      # Kvrocks laeuft als uid 999, sonst "Permission denied"
```

Compose: Restart-Policy, Host-Alias (für den Lookyloo-Worker):

```bash
python3 - <<'EOF'
import re
p = "docker-compose.yml"; s = open(p).read()
s = re.sub(r"^(  [a-z-]+:\n)", r"\1    restart: unless-stopped\n", s, flags=re.M)
s = s.replace("    ports:\n        - 6100:6100", '    extra_hosts:\n        - "host.docker.internal:host-gateway"\n    ports:\n        - 6100:6100')
open(p, "w").write(s)
EOF
```

Konfig: Kvrocks-Hostname für Compose, MISP, Lookyloo-Worker auf die eigene
Instanz, **alle Replicas auf 1** (ab Werk 51 Instanzen) und die Worker ohne
Nutzen abschalten. Jeder Pandora-Prozess trägt ~500 MB; die Zahl der Prozesse
ist der Speicherverbrauch.

```bash
python3 - <<'EOF'
import json, glob, re
c = json.load(open("config/generic.json"))
c["storage_db_hostname"] = "kvrocks"
key = open("/home/neo/misp.txt").read().strip(); assert key
c["misp"].update(url="https://misp.provinglab.de", apikey=key, tls_verify=False)
json.dump(c, open("config/generic.json", "w"), indent=4)

def edit(p, pairs):
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (p, old)
        s = s.replace(old, new)
    open(p, "w").write(s)
edit("pandora/workers/lookyloo.yml", [("  apiurl: https://lookyloo.circl.lu/", "  apiurl: http://host.docker.internal:5100/")])
edit("pandora/workers/misp.yml", [("  apikey: null", f"  apikey: {key}"),
                                  ("  apiurl: https://misp.example.com", "  apiurl: https://misp.provinglab.de"),
                                  ("  tls_verify: true", "  tls_verify: false")])
for p in glob.glob("pandora/workers/*.yml"):
    s = open(p).read()
    open(p, "w").write(re.sub(r"^(\s*replicas:\s*)\d+", r"\g<1>1", s, flags=re.M))
# ohne Nutzen fuer Phishing-Triage zu Hause: externe Sandboxes ohne Key, Malware-Repos, Riesen-YARA
for w in ("comodo", "hybridanalysis", "joesandbox", "mwdb", "malwarebazaar", "yarahq_full", "yarahub", "qrcode"):
    p = f"pandora/workers/{w}.yml"; s = open(p).read()
    if "disabled: true" in s: continue
    if "settings:" in s:
        s = s.replace("settings:\n", "settings:\n  disabled: true\n", 1)
    else:
        s += "\nsettings:\n  disabled: true\n"
    open(p, "w").write(s)
EOF
chmod 600 config/generic.json pandora/workers/misp.yml
shred -u /home/neo/misp.txt
docker compose build && docker compose up -d
```

Start dauert gut zwei Minuten (ClamAV lädt Signaturen, Pandora wartet 60 s,
LibreOffice startet). Dann `http://<ip>:6100`, eine harmlose PDF hochladen.

## 5. TLS, Namen, Zertifikat

`setup-nginx-tls.sh` (als root) stellt nginx vor beide Dienste und bindet 5100/6100 auf
127.0.0.1 (5100 zusätzlich auf docker0 für den Pandora-Worker). Ohne Argumente selbst
signiert auf 443/8443; mit `--names lookyloo.provinglab.de pandora.provinglab.de` beide auf
443 per SNI. Das Zertifikat kommt wie bei IRIS/Wazuh/MISP vom Relay:

```bash
# Pi-hole: beide Namen auf .232 (Settings > Local DNS Records)
# relay, als root:
~/.acme.sh/acme.sh --issue --dns dns_inwx --dnssleep 30 -d lookyloo.provinglab.de -d pandora.provinglab.de
~/.acme.sh/acme.sh --install-cert --ecc -d lookyloo.provinglab.de \
  --fullchain-file /root/.acme.sh/lookyloo.provinglab.de_ecc/fullchain.cer \
  --key-file /root/.acme.sh/lookyloo.provinglab.de_ecc/lookyloo.provinglab.de.key \
  --reloadcmd /root/deploy/triage.sh        # scp nach /etc/ssl/{certs,private}/triage.*, nginx reload
```

Der Relay-root braucht dafür seinen Key in `neo`s `authorized_keys` (nur diesen einen).
Pandoras `pandora/workers/lookyloo.yml` → `apiurl: https://lookyloo.provinglab.de/`, sonst
zeigen die Links in den Berichten ins Container-Netz (`LOOKYLOO_URL=… bash patch-pandora.sh`).

Grund für den ganzen Block ist Befund 48: über Klartext-HTTP sieht der Sensor jeden Upload
und meldet ihn, und die Triage-Schleife schließt sich.

## 6. Kontrolle

```bash
free -m | head -2
docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' | sort -k2 -h | tail -4
```

Ziel: beide Stacks zusammen unter 6 GB, `available` über 1,5 GB. Liegt
Pandora trotz Abspecken über 4 GB, gehört es auf einen Host mit mehr RAM;
Lookyloo bleibt, das ist der Teil, den man spontan braucht.

## Was beim ersten Mal schiefging (damit es niemand wiederholt)

| Symptom | Ursache | Fix |
|---|---|---|
| Load 30, alles im Zustand D, Gunicorn-Worker „SIGKILL, out of memory?“ | 4 GB RAM, kein Swap | 8 GB fest, Swap |
| VM sieht nur 4,8 von 8 GB | Proxmox-Ballooning ab 80 % Host-Auslastung | `--balloon 0`, andere VMs auf echten Bedarf verkleinern |
| Pandora-Build: „NumPy … X86_V2“ | CPU-Typ `kvm64` | `--cpu host` |
| Kvrocks „mkdir … Permission denied“ | Verzeichnisse gehören dem Benutzer, Container läuft als 999 | `chown 999:999 storage indexing` |
| Pandora „Waiting on storage to start“ | `storage_db_hostname` = 127.0.0.1 | `kvrocks` |
| Pandora „Waiting on storage to start“, Kvrocks „Restarting“ | `storage/db/LOG: Permission denied`, Unterverzeichnis gehört wieder dem Benutzer | `chown -R 999:999 storage indexing`; der Patch prüft seit heute rekursiv |
| Platte 100 %, Redis „MISCONF … unable to persist to disk“, ein Container-Log 16 GB | Platte voll durch Images und Build-Cache; Redis sperrt Schreibzugriffe; jeder Pandora-Worker loggt den Traceback im Millisekundentakt | Log mit `truncate -s0` leeren, `daemon.json` mit Log-Rotation, `down && up -d`, Platte vergrößern, `docker builder prune` nach Builds |
| `KeyError: 'MISP'` in modules.json | Block heißt `MultipleMISPs` | s. oben |
| Pandora 6 GB im Leerlauf | 51 Worker-Instanzen, 5 Gunicorn-Worker, 500 MB je Prozess | Replicas 1, Worker abschalten, 2 vCPUs |
| Stacks nach Reboot weg | Compose ohne Restart-Policy | `restart: unless-stopped` |
| Capture geht nicht über Tor | Container erreicht `127.0.0.1:9050` nicht | Tor auf `0.0.0.0` mit SocksPolicy, `host.docker.internal` |
| `--sshkeys` liefert alle Host-Keys | Datei des Hosts übernommen | eigene Key-Datei |

## Offen

- YARA in Pandora: `yara`, `yara_signature_base` sind ab Werk `disabled: true`,
  weil die Regelsätze erst geholt werden müssen. Für Phishing-Triage ohne
  Bedeutung; wenn gewünscht, Regeln ins Image, dann einschalten.
- Pandora-Worker, der URLs aus Observables an Lookyloo gibt (heute nur HTML).
- `helpers.py`-Sed in `patch-lookyloo.sh` entfernen, sobald PlaywrightCapture
  #267 im Release ist.
- Aufbewahrung der Captures (Lookyloo `archive`/`delete`-Fristen in generic.json).
- Nach jedem `compose build`: `docker builder prune -f`, sonst wächst der Cache.
- 5100 auf docker0 kann weg, seit der Pandora-Worker über den öffentlichen Namen geht.
- Watchdog-Checks für `.232`: 443 beide Namen, `compose ps` beider Stacks, `df -h /`.
