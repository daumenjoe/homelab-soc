#!/usr/bin/env bash
# Zündet einen Atomic auf redcanary, wartet, prüft ob die erwartete Wazuh-Regel gefeuert hat.
# Usage: ./run-atomic.sh <technique> <testnumber> <expected_rule_id> [wait_seconds]
set -u
TECH="$1"; NUM="$2"; RULE="$3"; WAIT="${4:-330}"
ATOMICS=/opt/atomic-red-team/atomics
MOD=/opt/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1

echo "== $TECH test $NUM -> erwarte Regel $RULE"
ssh -t redcanary "sudo pwsh -c \"Import-Module $MOD -Force; Invoke-AtomicTest $TECH -TestNumbers $NUM -PathToAtomicsFolder $ATOMICS\""
echo "-- warte ${WAIT}s auf Erkennung"
sleep "$WAIT"
HIT=$(ssh wazuh "sudo grep -ac '\"id\":\"$RULE\"' <(sudo tail -n 20000 /var/ossec/logs/alerts/alerts.json | grep -a redcanary)" 2>/dev/null)
# einfacher und robust: letzte passende Zeile zeigen
DESC=$(ssh wazuh "sudo grep -a '\"id\":\"$RULE\"' /var/ossec/logs/alerts/alerts.json | grep -a redcanary | tail -n 1 | grep -ao '\"description\":\"[^\"]*\"'")
if [ -n "$DESC" ]; then echo "ERKANNT: $DESC"; else echo "NICHT erkannt (Regel $RULE, Host redcanary)"; fi
echo "-- cleanup"
ssh -t redcanary "sudo pwsh -c \"Import-Module $MOD -Force; Invoke-AtomicTest $TECH -TestNumbers $NUM -Cleanup -PathToAtomicsFolder $ATOMICS\""
