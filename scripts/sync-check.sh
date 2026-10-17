#!/usr/bin/env bash
# sync-check.sh - Repo gegen die Live-Systeme abgleichen.
#
#   scripts/sync-check.sh            Unterschiede anzeigen (Standard)
#   scripts/sync-check.sh diff FILE  vollen Diff einer Datei zeigen (< repo, > live)
#   scripts/sync-check.sh pull       Live-Stand ins Repo uebernehmen (fragt vorher)
#
# Quellen:
#   wazuh:        /var/ossec/etc/rules/0*.xml, /var/ossec/etc/shared/*/agent.conf,
#                 /var/ossec/etc/lists/* (CDB-Quellen, nicht die .cdb)
#   velociraptor: Artefakt-Definitionen aus ARTIFACTS (unten)
#   pis:          Einzeldateien aus PI_FILES (unten), Format host:live:repo[:redact]
#                 "redact" schwaerzt Werte von token/password/secret/key/ntfy_url in JSON,
#                 im Repo liegt dann die geschwaerzte Fassung (z.B. *.example).
#
# Richtung ist bewusst nur live -> repo. Deploy ins System bleibt manuell,
# weil er einen Manager-Restart braucht, den man sehen will.
# Kein 2>/dev/null: wenn etwas schiefgeht, soll es sichtbar sein.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAZUH_HOST="wazuh"
VELO_HOST="velociraptor"
VELO_BIN="/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml"
ARTIFACTS=(Homelab.Events.Baseline Homelab.Events.FirewallState)
PI_FILES=(
    "pihole:/usr/local/bin/pihole_analytics.py:analytics/pihole_analytics.py"
    "watchdog:/usr/local/bin/homelab-watchdog.py:infra/watchdog/watchdog.py"
    "watchdog:/etc/watchdog.json:infra/watchdog/watchdog.json.example:redact"
    "wazuh:/var/ossec/integrations/custom-iris:integrations/custom-iris.py"
    "wazuh:/var/ossec/integrations/triage-spooler:integrations/triage-spooler.py"
    "wazuh:/etc/systemd/system/triage-spooler.service:integrations/triage-spooler.service"
    "wazuh:/etc/systemd/system/triage-spooler.timer:integrations/triage-spooler.timer"
)

RULES_DIR="$REPO/rules"
AGENT_DIR="$REPO/agent-configs"
VELO_DIR="$REPO/velociraptor"
LISTS_DIR="$REPO/lists"
# Wazuh-eigene Listen, die nicht ins Repo gehoeren
LIST_IGNORE=(audit-keys security-eventchannel)
# Lokale Regeldateien: umgebungsspezifische Overrides (Suffixe, Hostnamen),
# bewusst NICHT versioniert; werden geprueft (Dubletten), aber nie gepullt.
RULES_LOCAL=(0109-local_overrides.xml)
WORK="$(mktemp -d /tmp/sync-check.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

MODE="${1:-check}"

# ---------- Live-Stand holen ----------
fetch_live() {
    echo "== hole Live-Stand =="
    # Regeln + Gruppen-Konfigs als Tar (Dateien gehoeren wazuh:640, daher sudo+tar)
    ssh "$WAZUH_HOST" "sudo tar czf /tmp/sync-live.tgz -C /var/ossec/etc --exclude='*.cdb' rules shared lists && sudo chown \$(id -un) /tmp/sync-live.tgz"
    scp -q "$WAZUH_HOST:/tmp/sync-live.tgz" "$WORK/"
    ssh "$WAZUH_HOST" "rm /tmp/sync-live.tgz"
    tar xzf "$WORK/sync-live.tgz" -C "$WORK"
    # nur eure Custom-Regeln (0xxx), nicht local_rules.xml
    mkdir -p "$WORK/live-rules"
    find "$WORK/rules" -maxdepth 1 -name '0*.xml' -exec cp {} "$WORK/live-rules/" \;
    # Artefakte
    mkdir -p "$WORK/live-velo"
    for a in "${ARTIFACTS[@]}"; do
        ssh "$VELO_HOST" "$VELO_BIN artifacts show $a" > "$WORK/live-velo/$a.yaml"
    done
    # Einzeldateien auf den Pis
    mkdir -p "$WORK/live-pi"
    for spec in "${PI_FILES[@]}"; do
        IFS=: read -r host live repo flag <<< "$spec"
        dest="$WORK/live-pi/$repo"; mkdir -p "$(dirname "$dest")"
        ssh "$host" "sudo cat '$live'" > "$dest"
        if [[ "${flag:-}" == "redact" ]]; then
            python3 - "$dest" <<'PY'
import json, re, sys
p = sys.argv[1]
SECRET = re.compile(r"(token|password|passwd|secret|api_?key|ntfy_url)$", re.I)
def walk(o):
    if isinstance(o, dict):
        return {k: ("<REDACTED>" if SECRET.search(k) and isinstance(v, str) else walk(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [walk(v) for v in o]
    return o
d = walk(json.load(open(p)))
with open(p, "w") as f:
    json.dump(d, f, indent=2, ensure_ascii=False); f.write("\n")
PY
        fi
    done
    echo "   $(ls "$WORK/live-rules" | wc -l) Regeldateien, $(ls "$WORK/shared" | wc -l) Gruppen, $(ls "$WORK/lists" | wc -l) Liste(n), ${#ARTIFACTS[@]} Artefakt(e), ${#PI_FILES[@]} Pi-Datei(en)"
}

# ---------- Dubletten ----------
# Regel-IDs, die in mehreren Dateien stehen, OHNE dass die weiteren Definitionen
# overwrite="yes" tragen: Wazuh verwirft dann eine davon stillschweigend.
# Overrides (0109 lokal, 09xx) sind erlaubt und werden als Hinweis gelistet.
check_dupes() {
    local dir="$1" label="$2"
    python3 - "$dir" "$label" <<'PY'
import re, sys, glob, collections
d, label = sys.argv[1], sys.argv[2]
defs = collections.defaultdict(list)
for f in sorted(glob.glob(d + "/*.xml")):
    for m in re.finditer(r'<rule\s+([^>]*?)>', open(f, encoding="utf-8", errors="replace").read()):
        attrs = m.group(1)
        rid = re.search(r'id="(\d+)"', attrs)
        if rid:
            defs[rid.group(1)].append((f.rsplit("/", 1)[-1], 'overwrite="yes"' in attrs))
bad, over = [], []
for rid, lst in defs.items():
    if len(lst) < 2: continue
    n_over = sum(1 for _, o in lst if o)
    (over if n_over >= len(lst) - 1 else bad).append((rid, [f for f, _ in lst]))
for rid, files in sorted(over):
    print(f"   override  {label} {rid}: " + " -> ".join(files))
for rid, files in sorted(bad):
    print(f"   DUBLETTE  {label} {rid}: " + ", ".join(files) + "  (kein overwrite: eine Definition ist tot)")
PY
}

# ---------- Vergleich ----------
# Gibt Zeilen aus:  STATUS  PFAD-IM-REPO  LIVE-PFAD
#   same / differs / only-live / only-repo
compare() {
    # Regeln
    for f in "$WORK/live-rules"/*.xml; do
        b="$(basename "$f")"
        [[ " ${RULES_LOCAL[*]} " == *" $b "* ]] && continue
        if [[ -f "$RULES_DIR/$b" ]]; then
            if diff -q "$f" "$RULES_DIR/$b" >/dev/null; then echo "same      rules/$b"; else echo "differs   rules/$b  $f"; fi
        else
            echo "only-live rules/$b  $f"
        fi
    done
    for f in "$RULES_DIR"/0*.xml; do
        b="$(basename "$f")"
        [[ -f "$WORK/live-rules/$b" ]] || echo "only-repo rules/$b"
    done
    # agent.conf je Gruppe
    for g in "$WORK/shared"/*/; do
        gn="$(basename "$g")"
        [[ -f "$g/agent.conf" ]] || continue
        if [[ -f "$AGENT_DIR/$gn/agent.conf" ]]; then
            if diff -q "$g/agent.conf" "$AGENT_DIR/$gn/agent.conf" >/dev/null; then echo "same      agent-configs/$gn/agent.conf"; else echo "differs   agent-configs/$gn/agent.conf  $g/agent.conf"; fi
        else
            echo "only-live agent-configs/$gn/agent.conf  $g/agent.conf"
        fi
    done
    # CDB-Listen (Quelldateien)
    for f in "$WORK/lists"/*; do
        [[ -f "$f" ]] || continue
        b="$(basename "$f")"
        [[ " ${LIST_IGNORE[*]} " == *" $b "* ]] && continue
        if [[ -f "$LISTS_DIR/$b" ]]; then
            if diff -q "$f" "$LISTS_DIR/$b" >/dev/null; then echo "same      lists/$b"; else echo "differs   lists/$b  $f"; fi
        else
            echo "only-live lists/$b  $f"
        fi
    done
    # Artefakte
    for a in "${ARTIFACTS[@]}"; do
        if [[ -f "$VELO_DIR/$a.yaml" ]]; then
            if diff -q "$WORK/live-velo/$a.yaml" "$VELO_DIR/$a.yaml" >/dev/null; then echo "same      velociraptor/$a.yaml"; else echo "differs   velociraptor/$a.yaml  $WORK/live-velo/$a.yaml"; fi
        else
            echo "only-live velociraptor/$a.yaml  $WORK/live-velo/$a.yaml"
        fi
    done
    # Pi-Dateien
    for spec in "${PI_FILES[@]}"; do
        IFS=: read -r host live repo flag <<< "$spec"
        if [[ -f "$REPO/$repo" ]]; then
            if diff -q "$WORK/live-pi/$repo" "$REPO/$repo" >/dev/null; then echo "same      $repo"; else echo "differs   $repo  $WORK/live-pi/$repo"; fi
        else
            echo "only-live $repo  $WORK/live-pi/$repo"
        fi
    done
}

# ---------- Modi ----------
case "$MODE" in
  check)
    fetch_live
    echo
    echo "== Regel-IDs (live) =="
    check_dupes "$WORK/live-rules" live
    echo
    echo "== Abgleich (repo <-> live) =="
    compare | awk '$1!="same"' | sort > "$WORK/report"
    if [[ ! -s "$WORK/report" ]]; then
        echo "   alles gleich - Repo entspricht den Systemen"
    else
        awk '{printf "   %-10s %s\n", $1, $2}' "$WORK/report"
        echo
        echo "   vollen Diff zeigen:  $0 diff <pfad>"
        echo "   uebernehmen:         $0 pull"
    fi
    ;;

  diff)
    [[ -n "${2:-}" ]] || { echo "usage: $0 diff rules/0100-pihole_rules.xml"; exit 1; }
    fetch_live
    live="$(compare | awk -v p="$2" '$2==p {print $3}')"
    [[ -n "$live" ]] || { echo "kein Live-Gegenstueck fuer $2 (gleich, oder nur im Repo)"; exit 1; }
    echo
    echo "== $2   (< repo, > live) =="
    diff "$REPO/$2" "$live" || true
    ;;

  pull)
    fetch_live
    echo
    check_dupes "$WORK/live-rules" live | grep DUBLETTE && { echo "   erst Dubletten beheben, dann pull"; exit 1; }
    compare | awk '$1=="differs" || $1=="only-live"' > "$WORK/todo"
    if [[ ! -s "$WORK/todo" ]]; then echo "nichts zu uebernehmen"; exit 0; fi
    echo "== wuerde ins Repo uebernehmen =="
    awk '{printf "   %-10s %s\n", $1, $2}' "$WORK/todo"
    compare | awk '$1=="only-repo"{print "   HINWEIS nur im repo (bleibt, ggf. git rm): "$2}'
    echo
    read -r -p "uebernehmen? [y/N] " ans
    [[ "$ans" == "y" ]] || { echo "abgebrochen"; exit 0; }
    while read -r status dest src; do
        mkdir -p "$(dirname "$REPO/$dest")"
        cp "$src" "$REPO/$dest"
        echo "   -> $dest"
    done < "$WORK/todo"
    echo
    echo "fertig. jetzt: git status, TUNING.md, commit."
    ;;

  *)
    echo "usage: $0 [check|diff FILE|pull]"; exit 1 ;;
esac
