#!/usr/bin/env bash
# Zieht die produktiven Dateien von Wazuh-Manager und Pi-hole ins Repo.
# Quelle der Wahrheit ist das laufende System, nicht ein Chat-Verlauf.
#
#   MGR=root@wazuh PI=pi@192.168.178.251 ./scripts/collect.sh
#
# Fehlende Dateien werden gemeldet, brechen den Lauf aber nicht ab.
set -uo pipefail

MGR="${MGR:-root@wazuh}"
PI="${PI:-pi@192.168.178.251}"
GROUP="${GROUP:-pihole}"          # Wazuh-Agent-Gruppe
SUDO="${SUDO-sudo}"               # SUDO="" wenn direkt als root
UNIT_GLOB="${UNIT_GLOB:-pihole-analytics*}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
MISSING=0

fetch() {  # fetch <host> <remote-file> <local-dir>
  local host=$1 remote=$2 dir=$3
  mkdir -p "$dir"
  if ssh -n "$host" "$SUDO test -f '$remote'"; then
    ssh -n "$host" "$SUDO cat '$remote'" > "$dir/$(basename "$remote")"
    printf 'ok    %s:%s\n' "$host" "$remote"
  else
    printf 'MISS  %s:%s\n' "$host" "$remote" >&2
    MISSING=$((MISSING + 1))
  fi
}

fetch_glob() {  # fetch_glob <host> <remote-glob> <local-dir>
  local host=$1 glob=$2 dir=$3 files
  mapfile -t files < <(ssh -n "$host" "$SUDO sh -c 'ls -1d $glob 2>/dev/null'")
  if [[ ${#files[@]} -eq 0 ]]; then
    printf 'MISS  %s:%s (kein Treffer)\n' "$host" "$glob" >&2
    MISSING=$((MISSING + 1))
    return
  fi
  for f in "${files[@]}"; do fetch "$host" "$f" "$dir"; done
}

echo "== Wazuh-Manager ($MGR)"
fetch_glob "$MGR" '/var/ossec/etc/decoders/01[0-9][0-9]-*.xml' "$REPO/decoders"
fetch_glob "$MGR" '/var/ossec/etc/rules/01[0-9][0-9]-*.xml'    "$REPO/rules"
fetch      "$MGR" '/var/ossec/etc/lists/dns-allow'             "$REPO/lists"
fetch      "$MGR" "/var/ossec/etc/shared/$GROUP/agent.conf"    "$REPO/agent"

echo "== Pi-hole ($PI)"
# systemd-Units (Service + Timer; NRD-Updater ggf. über UNIT_GLOB ergänzen)
fetch_glob "$PI" "/etc/systemd/system/$UNIT_GLOB" "$REPO/analytics/systemd"

# Skriptpfade aus den Units ablesen statt raten
mapfile -t scripts < <(ssh -n "$PI" \
  "grep -hoE '(/[A-Za-z0-9._-]+)+\.(py|sh)' /etc/systemd/system/$UNIT_GLOB 2>/dev/null | sort -u")
if [[ ${#scripts[@]} -eq 0 ]]; then
  echo "MISS  kein Skriptpfad in den Units gefunden" >&2
  MISSING=$((MISSING + 1))
fi
for s in "${scripts[@]}"; do fetch "$PI" "$s" "$REPO/analytics"; done

fetch_glob "$PI" '/etc/pihole-analytics/*.json'      "$REPO/analytics/config"
fetch_glob "$PI" '/etc/pihole-analytics/*.txt'       "$REPO/analytics/config"
fetch      "$PI" '/etc/logrotate.d/pihole-analytics' "$REPO/analytics/logrotate"

fetch_glob "$PI" '/etc/unbound/unbound.conf.d/*.conf' "$REPO/unbound"
fetch      "$PI" '/etc/logrotate.d/unbound'           "$REPO/unbound/logrotate"

echo
echo "Fertig, $MISSING Quelle(n) nicht gefunden."
echo "Als Nächstes: ./scripts/check-public.sh  und  git diff"
