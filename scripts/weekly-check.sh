#!/usr/bin/env bash
# weekly-check.sh - Wochencheck: sieben Tage als Zeilen, Zaehler als Spalten.
#
#   scripts/weekly-check.sh          letzte 7 Tage (heute eingeschlossen)
#   scripts/weekly-check.sh 14       letzte 14 Tage
#
# Loest daily-check.sh ab, seit die Baseline steht (Befund 46): einmal pro Woche
# die Zahlen, dazu die IRIS-Liste lesen (Befund 42). Liest nur, aendert nichts.
# Alle Zugriffe per ssh-Alias (wazuh, pve, pihole, watchdog), passwortloses sudo.
# Archivtage kommen aus ossec-alerts-DD.json.gz, der laufende Tag aus alerts.json.
# Kein 2>/dev/null: wenn etwas schiefgeht, soll es sichtbar sein.
#
# Sollwerte:
#   NIC-Haenger        0
#   L>=2 je Tag        ~500 ohne Laptop, ~2800 mit (PAM/sudo vom Arbeitstag)
#   110040 (L5)        geblockte Wiederholschleifen; zaehlt, kein IRIS-Fall mehr
#   110061             Retry-Loops bekannte Telemetrie, TV-Betrieb
#   110086 / 110184    0 ohne Test
#   110157             WLAN-Flapping je Geraet (10 Joins/h)
#   110173 / 110172    0; jeder Treffer wird angesehen (Deauth-Flut, Evil Twin)
#   L>=10              0 ohne Test
#   Spool              leer, sobald der llm einmal am Tag lief

set -uo pipefail

DAYS="${1:-7}"
WAZUH_HOST="wazuh"
PVE_HOST="pve"
PIHOLE_HOST="pihole"
WATCHDOG_HOST="watchdog"
ALERTS="/var/ossec/logs/alerts/alerts.json"
ARCHIVE="/var/ossec/logs/alerts"
INTEGRATIONS="/var/ossec/logs/integrations.log"
SPOOL="/var/ossec/var/triage-spool"
RULES="110040 110061 110086 110184 110157 110173 110172"

hdr() { printf '\n-- %s\n' "$*"; }

echo "== Wochencheck $(date -d "-$((DAYS-1)) days" +%F) bis $(date +%F) =="

hdr "NIC-Haenger auf $PVE_HOST seit Boot (soll 0):"
ssh "$PVE_HOST" "journalctl -k -b | grep -c 'Hardware Unit Hang'"

# ---------- Tagestabelle: ein jq-Lauf je Tag auf dem Manager ----------
hdr "Alerts je Tag (L>=2) und Zaehler:"
ssh "$WAZUH_HOST" "DAYS=$DAYS ALERTS=$ALERTS ARCHIVE=$ARCHIVE INTEGRATIONS=$INTEGRATIONS RULES='$RULES' bash -s" <<'EOF'
printf '%-10s %6s' Tag 'L>=2'
for r in $RULES; do printf ' %6s' "$r"; done
printf ' %5s %5s %6s %5s\n' 'L>=10' IRIS spool nachg
for i in $(seq $((DAYS-1)) -1 0); do
    day=$(date -d "-$i days" +%F)
    if [ "$i" -eq 0 ]; then
        src="cat $ALERTS"
    else
        f="$ARCHIVE/$(LC_ALL=C date -d "-$i days" +%Y/%b)/ossec-alerts-$(date -d "-$i days" +%d).json.gz"
        sudo test -f "$f" || { printf '%-10s %s\n' "$day" "kein Archiv: $f"; continue; }
        src="zcat $f"
    fi
    # eine Zeile je Alert: "<level> <id>", dann in awk zaehlen
    sudo bash -c "$src" | jq -R -r 'fromjson? | select(.rule.level>=2) | "\(.rule.level) \(.rule.id)"' \
    | awk -v rules="$RULES" -v day="$day" '
        BEGIN { n = split(rules, R, " ") }
        { total++; if ($1 >= 10) hi++; c[$2]++ }
        END {
            printf "%-10s %6d", day, total
            for (i = 1; i <= n; i++) printf " %6d", c[R[i]] + 0
            printf " %5d", hi + 0
        }'
    iris=$(sudo grep "^$day" $INTEGRATIONS | grep -c 'custom-iris: rule .* -> IRIS alert')
    sp=$(sudo grep "^$day" $INTEGRATIONS | grep -c 'spooled for later')
    nd=$(sudo grep "^$day" $INTEGRATIONS | grep -c 'triage-spooler: alert .* -> ')
    printf ' %5d %6d %5d\n' "$iris" "$sp" "$nd"
done
EOF

hdr "Spool jetzt:"
ssh "$WAZUH_HOST" "sudo -u wazuh /var/ossec/integrations/triage-spooler --list | tail -1"

# ---------- Wochen-Top-10 ----------
hdr "Top-10 Regeln der Woche (L>=2):"
ssh "$WAZUH_HOST" "DAYS=$DAYS ALERTS=$ALERTS ARCHIVE=$ARCHIVE bash -s" <<'EOF'
for i in $(seq $((DAYS-1)) -1 0); do
    if [ "$i" -eq 0 ]; then sudo cat $ALERTS; else
        f="$ARCHIVE/$(LC_ALL=C date -d "-$i days" +%Y/%b)/ossec-alerts-$(date -d "-$i days" +%d).json.gz"
        sudo test -f "$f" && sudo zcat "$f"
    fi
done | jq -R -r 'fromjson? | select(.rule.level>=2) | .rule.id + "  " + .rule.description[0:80]' | sort | uniq -c | sort -rn | head -10
EOF

hdr "Alerts L>=10 der Woche (Regel, Agent, Anzahl, erstes/letztes Mal; soll leer ohne Test):"
ssh "$WAZUH_HOST" "DAYS=$DAYS ALERTS=$ALERTS ARCHIVE=$ARCHIVE bash -s" <<'EOF'
for i in $(seq $((DAYS-1)) -1 0); do
    if [ "$i" -eq 0 ]; then sudo cat $ALERTS; else
        f="$ARCHIVE/$(LC_ALL=C date -d "-$i days" +%Y/%b)/ossec-alerts-$(date -d "-$i days" +%d).json.gz"
        sudo test -f "$f" && sudo zcat "$f"
    fi
done | jq -R -r 'fromjson? | select(.rule.level>=10) | [.rule.id, .agent.name, .timestamp[5:16], .rule.description[0:60]] | @tsv' \
   | awk -F'\t' '{ k=$1 " " $2; n[k]++; if (!(k in first)) first[k]=$3; last[k]=$3; d[k]=$4 }
                END { for (k in n) printf "   %6d  %-22s %s .. %s  %s\n", n[k], k, first[k], last[k], d[k] }' | sort -rn | head -20
EOF

hdr "Triage der Woche nach Regel (custom-iris, Top-5):"
ssh "$WAZUH_HOST" "sudo grep -E '^($(for i in $(seq $((DAYS-1)) -1 0); do date -d "-$i days" +%F; done | paste -sd'|'))' $INTEGRATIONS | grep 'custom-iris: rule' | grep -oE 'rule [0-9]+' | sort | uniq -c | sort -rn | head -5"

# ---------- Pi-hole je Tag ----------
hdr "Pi-hole je Tag (FTL-DB): Anfragen, Blocks, Block-Anteil:"
ssh "$PIHOLE_HOST" sudo python3 - "$DAYS" <<'EOF'
import sqlite3, datetime, sys
days = int(sys.argv[1])
blocked = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)
t0 = (datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
      - datetime.timedelta(days=days - 1)).timestamp()
db = sqlite3.connect("file:/etc/pihole/pihole-FTL.db?mode=ro", uri=True)
sql = ("SELECT date(timestamp, 'unixepoch', 'localtime') AS d, COUNT(*), "
       "SUM(CASE WHEN status IN (%s) THEN 1 ELSE 0 END) FROM queries WHERE timestamp >= ? "
       "GROUP BY d ORDER BY d" % ",".join(map(str, blocked)))
for d, n, b in db.execute(sql, (t0,)):
    print(f"{d} {n:7d} {b:6d}  {100*b/n:4.1f}%  " + "#" * (b // 250))
EOF

hdr "Watchdog, letzter Lauf (nur BAD, leer = alles gruen):"
ssh "$WATCHDOG_HOST" "journalctl -u homelab-watchdog -n 25 --no-pager | grep ' BAD ' || true"

echo
echo "== fertig =="
