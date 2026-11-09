#!/usr/bin/env bash
# build-triage-vm.sh - Lookyloo-Triage-VM auf einem Proxmox-Host unbeaufsichtigt anlegen.
#
# Laeuft als root auf dem Proxmox-Host, patch-lookyloo.sh muss daneben liegen. Legt die VM aus
# dem Debian-13-Cloud-Image an und erzeugt ein Cloud-Init-Userdata, das beim ersten Boot alles
# einrichtet: Pakete, Docker (offizielles Repo, Log-Rotation 3x50 MB), optional Tor, Swap, Lookyloo
# mit Patches, Build, Start. Platte 64 GB: zwei selbstgebaute Images plus Build-Cache belegen ~30 GB,
# mit 40 GB lief die Platte voll, Redis ging in MISCONF und die Pandora-Worker loggten 16 GB in Minuten. Erster Boot dauert 5-10 Minuten (Chromium-Download, Image-Build); Protokoll im Gast unter
# /var/log/cloud-init-output.log. Danach antwortet http://<ip>:5100.
#
#   ./build-triage-vm.sh --vmid 110 --name triage-test --ip 192.168.178.233/24 --gw 192.168.178.1 \
#       --dns 192.168.178.251 --sshkey /root/triage-key.pub \
#       --misp-url https://misp.provinglab.de --misp-key-file /root/misp.txt --apt-proxy http://192.168.178.230:3142
#   ./build-triage-vm.sh --vmid 120 --ip 192.168.30.229/22 --gw 192.168.30.1 \
#       --dns "192.168.31.246 192.168.250.20" --password-file /root/neo.pw [--no-tor]
#
# Optionen: --name (triage) --storage (local-lvm) --bridge (vmbr0) --cores (2) --memory (10240)
#           --user (neo) --sshkey DATEI | --password-file DATEI  --misp-url URL --misp-key-file DATEI
#           --apt-proxy URL  --no-tor
# Voraussetzung: Storage "local" hat den Inhaltstyp "Snippets" (Datacenter > Storage > local > Edit).
# Kein 2>/dev/null: wenn etwas schiefgeht, soll es sichtbar sein.

set -euo pipefail

VMID=""; NAME="triage"; IP=""; GW=""; DNS=""; STORAGE="local-lvm"; BRIDGE="vmbr0"
CORES=2; MEMORY=10240; DISK_ADD="+62G"; CIUSER="neo"; SSHKEY=""; PWFILE=""
MISP_URL=""; MISP_KEY_FILE=""; APT_PROXY=""; TOR=1
IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
IMAGE="/var/lib/vz/template/$(basename "$IMAGE_URL")"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { sed -n '2,20p' "$0"; exit 1; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmid) VMID="$2"; shift ;;          --name) NAME="$2"; shift ;;
        --ip) IP="$2"; shift ;;              --gw) GW="$2"; shift ;;
        --dns) DNS="$2"; shift ;;            --storage) STORAGE="$2"; shift ;;
        --bridge) BRIDGE="$2"; shift ;;      --cores) CORES="$2"; shift ;;
        --memory) MEMORY="$2"; shift ;;      --user) CIUSER="$2"; shift ;;
        --sshkey) SSHKEY="$2"; shift ;;      --password-file) PWFILE="$2"; shift ;;
        --misp-url) MISP_URL="$2"; shift ;;  --misp-key-file) MISP_KEY_FILE="$2"; shift ;;
        --apt-proxy) APT_PROXY="$2"; shift ;; --no-tor) TOR=0 ;;
        -h|--help) usage ;;
        *) echo "unbekannte Option: $1"; usage ;;
    esac
    shift
done
[[ -n "$VMID" && -n "$IP" && -n "$GW" && -n "$DNS" ]] || { echo "--vmid, --ip, --gw, --dns sind Pflicht"; usage; }
[[ -n "$SSHKEY" || -n "$PWFILE" ]] || { echo "--sshkey oder --password-file angeben"; exit 1; }
[[ -f "$HERE/patch-lookyloo.sh" ]] || { echo "patch-lookyloo.sh fehlt neben dem Skript"; exit 1; }
[[ -z "$SSHKEY" || -f "$SSHKEY" ]] || { echo "Key-Datei fehlt: $SSHKEY"; exit 1; }
[[ -z "$PWFILE" || -f "$PWFILE" ]] || { echo "Passwort-Datei fehlt: $PWFILE"; exit 1; }
[[ -z "$MISP_KEY_FILE" || -f "$MISP_KEY_FILE" ]] || { echo "MISP-Key-Datei fehlt: $MISP_KEY_FILE"; exit 1; }
[[ -z "$MISP_URL" || -n "$MISP_KEY_FILE" ]] || { echo "--misp-url braucht --misp-key-file"; exit 1; }
if [[ -f "/etc/pve/qemu-server/$VMID.conf" ]]; then echo "VM $VMID existiert schon"; exit 1; fi

echo "== Image"
[[ -f "$IMAGE" ]] || curl -L -o "$IMAGE" "$IMAGE_URL"

echo "== Userdata erzeugen"
mkdir -p /var/lib/vz/snippets
SNIPPET="/var/lib/vz/snippets/${NAME}-${VMID}-user.yaml"
export NAME CIUSER MISP_URL APT_PROXY TOR
export PWHASH=""; [[ -n "$PWFILE" ]] && PWHASH="$(openssl passwd -6 "$(head -1 "$PWFILE")")"
export SSHKEY_LINE=""; [[ -n "$SSHKEY" ]] && SSHKEY_LINE="$(head -1 "$SSHKEY")"
export MISP_KEY=""; [[ -n "$MISP_KEY_FILE" ]] && MISP_KEY="$(head -1 "$MISP_KEY_FILE")"
export PATCH_B64="$(base64 -w0 "$HERE/patch-lookyloo.sh")"
python3 - "$SNIPPET" <<'PYEOF'
import base64, json, os, sys
e = os.environ
user, home = e["CIUSER"], f"/home/{e['CIUSER']}"
tor, proxy, misp = e["TOR"] == "1", e["APT_PROXY"], e["MISP_URL"]

# --- Dateien, die Cloud-Init vor runcmd ablegt
files = []
def add(path, content, perms="0644", owner="root:root"):
    files.append({"path": path, "permissions": perms, "owner": owner,
                  "encoding": "b64", "content": base64.b64encode(content.encode()).decode()})
if proxy:
    add("/etc/apt/apt.conf.d/01proxy", f'Acquire::http::Proxy "{proxy}";\nAcquire::https::Proxy "DIRECT";\n')
add("/etc/apt/sources.list.d/docker.sources",
    "Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: trixie\nComponents: stable\n"
    "Architectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n")
add("/etc/docker/daemon.json",
    '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "50m", "max-file": "3" }\n}\n')
files.append({"path": "/root/patch-lookyloo.sh", "permissions": "0755", "encoding": "b64", "content": e["PATCH_B64"]})
if misp:
    add("/root/misp.txt", e["MISP_KEY"] + "\n", "0600")
proxy_srv = "socks5://host.docker.internal:9050"
add("/root/configure-lookyloo.py", f'''import json, os
os.chdir("{home}/stacks/lookyloo")
for f in ("generic", "logging", "logging_web", "modules"):
    if not os.path.exists(f"config/{{f}}.json"):
        open(f"config/{{f}}.json", "w").write(open(f"config/{{f}}.json.sample").read())
c = json.load(open("config/generic.json"))
if {tor!r}:
    c["global_proxy"].update(enable=True, server="{proxy_srv}")
    c["tor_proxy"]["server"] = "{proxy_srv}"
json.dump(c, open("config/generic.json", "w"), indent=2)
if {bool(misp)!r}:
    key = open("/root/misp.txt").read().strip()
    c = json.load(open("config/modules.json"))
    c["MultipleMISPs"]["instances"]["MISP"].update(apikey=key, url="{misp}", verify_tls_cert=False,
        enable_lookup=True, enable_push=True, default_tags=["source:lookyloo"])
    json.dump(c, open("config/modules.json", "w"), indent=2)
    os.chmod("config/modules.json", 0o600)
print("lookyloo konfiguriert")
''', "0700")

# --- Benutzer
u = {"name": user, "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL", "groups": "sudo"}
if e["SSHKEY_LINE"]:
    u["ssh_authorized_keys"] = [e["SSHKEY_LINE"]]
if e["PWHASH"]:
    u["lock_passwd"] = False; u["passwd"] = e["PWHASH"]
else:
    u["lock_passwd"] = True

# --- Ablauf beim ersten Boot
run = [
    "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab",
    "echo 'de_DE.UTF-8 UTF-8' >> /etc/locale.gen && locale-gen",
    "install -m 0755 -d /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc",
    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
    f"usermod -aG docker {user}",
    "systemctl enable --now qemu-guest-agent",
]
if tor:
    run += ["printf 'SocksPort 0.0.0.0:9050\\nSocksPolicy accept 172.16.0.0/12\\nSocksPolicy accept 127.0.0.1\\nSocksPolicy reject *\\n' >> /etc/tor/torrc && systemctl restart tor"]
run += [
    f"mkdir -p {home}/stacks && git clone --depth 1 https://github.com/Lookyloo/lookyloo.git {home}/stacks/lookyloo",
    f"cp /root/patch-lookyloo.sh {home}/stacks/lookyloo/ && bash {home}/stacks/lookyloo/patch-lookyloo.sh",
    "python3 /root/configure-lookyloo.py",
    f"chown -R {user}:{user} {home}/stacks",
    f"cd {home}/stacks/lookyloo && docker compose build && docker compose up -d",
    "shred -u /root/misp.txt /root/configure-lookyloo.py || true",
    "echo TRIAGE-SETUP-DONE",
]

cfg = {
    "hostname": e["NAME"], "manage_etc_hosts": True,
    "users": [u], "ssh_pwauth": bool(e["PWHASH"]),
    "package_update": True, "package_upgrade": False,
    "packages": ["ca-certificates", "curl", "git", "qemu-guest-agent", "locales"] + (["tor"] if tor else []),
    "write_files": files,
    "runcmd": run,
    "final_message": "cloud-init fertig nach $UPTIME s; Lookyloo-Status: docker compose ps in " + home + "/stacks/lookyloo",
}
open(sys.argv[1], "w").write("#cloud-config\n" + json.dumps(cfg, indent=2) + "\n")   # JSON ist gueltiges YAML
PYEOF
chmod 600 "$SNIPPET"
echo "   $SNIPPET"

echo "== VM $VMID ($NAME) anlegen"
qm create "$VMID" --name "$NAME" --ostype l26 --cpu host --cores "$CORES" --memory "$MEMORY" --balloon 0 \
    --scsihw virtio-scsi-single --net0 "virtio,bridge=$BRIDGE" --agent enabled=1 \
    --serial0 socket --vga serial0 --onboot 1
qm importdisk "$VMID" "$IMAGE" "$STORAGE"
qm set "$VMID" --scsi0 "$STORAGE:vm-$VMID-disk-0,discard=on" --boot order=scsi0
qm resize "$VMID" scsi0 "$DISK_ADD"
qm set "$VMID" --ide2 "$STORAGE:cloudinit" --ipconfig0 "ip=$IP,gw=$GW" --nameserver "$DNS" \
    --cicustom "user=local:snippets/$(basename "$SNIPPET")"
qm start "$VMID"
echo
echo "VM $VMID laeuft. Erster Boot richtet alles ein (5-10 min). Fortschritt:"
echo "   ssh $CIUSER@${IP%/*} 'tail -f /var/log/cloud-init-output.log'     (Ende: TRIAGE-SETUP-DONE)"
echo "Fertig, wenn:  curl -s -o /dev/null -w '%{http_code}\\n' http://${IP%/*}:5100/   ->  302"
