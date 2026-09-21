#!/usr/bin/env bash
# Fetch the newly-registered-domains feed from smet.cz (CC BY 4.0, attribution
# required: https://smet.cz/nrd/) and import it into the SQLite lookup DB used
# by pihole_analytics.py. Any plain-text / hosts list URL works as NRD_URL.
set -euo pipefail

NRD_URL="${NRD_URL:-https://smet.cz/nrd/data/30d.txt.gz}"
NRD_DB="${NRD_DB:-/var/lib/pihole-analytics/nrd.db}"
ANALYTICS="${ANALYTICS:-/usr/local/bin/pihole_analytics.py}"
MIN_ENTRIES="${MIN_ENTRIES:-100000}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL --retry 3 --max-time 900 "$NRD_URL" -o "$WORK/list.raw"

case "$NRD_URL" in
  *.gz) gunzip -c "$WORK/list.raw" > "$WORK/list.txt" ;;
  *)    mv "$WORK/list.raw" "$WORK/list.txt" ;;
esac

LINES=$(wc -l < "$WORK/list.txt")
if (( LINES < MIN_ENTRIES )); then
  echo "refusing to import list with only $LINES lines (MIN_ENTRIES=$MIN_ENTRIES)" >&2
  exit 3
fi

NRD_URL="$NRD_URL" python3 "$ANALYTICS" import-nrd "$WORK/list.txt" "$NRD_DB"
