#!/usr/bin/env bash
# Auf dem Wazuh-Manager im Repo-Checkout ausführen (root).
# Kopiert Decoder/Regeln, testet die Konfiguration, rollt bei Fehler zurück.
#
#   ./scripts/deploy-manager.sh [--with-lists]
#
# lists/dns-allow wird nur mit --with-lists überschrieben, weil die
# produktive Allowlist meist weiter ist als die kuratierte im Repo.
set -euo pipefail

OSSEC=/var/ossec
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WITH_LISTS=0
[[ "${1:-}" == "--with-lists" ]] && WITH_LISTS=1

BACKUP="$OSSEC/backup/dns-detection-$(date +%Y%m%d-%H%M%S)"
NEW=()   # Dateien, die es vorher nicht gab (bei Rollback löschen)
mkdir -p "$BACKUP/decoders" "$BACKUP/rules" "$BACKUP/lists"

put() {  # put <src> <subdir>
  local src=$1 sub=$2
  local dst="$OSSEC/etc/$sub/$(basename "$src")"
  if [[ -f "$dst" ]]; then cp -p "$dst" "$BACKUP/$sub/"; else NEW+=("$dst"); fi
  install -o wazuh -g wazuh -m 660 "$src" "$dst"
  echo "-> $dst"
}

shopt -s nullglob
for f in "$REPO"/decoders/*.xml; do put "$f" decoders; done
for f in "$REPO"/rules/*.xml;    do put "$f" rules;    done
if [[ $WITH_LISTS -eq 1 && -f "$REPO/lists/dns-allow" ]]; then
  put "$REPO/lists/dns-allow" lists
else
  echo "(lists/dns-allow übersprungen)"
fi

echo "== Konfigurationstest"
if ! "$OSSEC/bin/wazuh-analysisd" -t; then
  echo "!! Test fehlgeschlagen, stelle vorherigen Stand wieder her" >&2
  for sub in decoders rules lists; do
    for f in "$BACKUP/$sub"/*; do cp -p "$f" "$OSSEC/etc/$sub/"; done
  done
  for f in ${NEW[@]+"${NEW[@]}"}; do rm -f "$f"; done
  exit 1
fi

systemctl restart wazuh-manager
echo "OK. Backup liegt in $BACKUP"
echo "Jetzt: ./tests/run-logtest.sh"
