#!/usr/bin/env bash
# Regressionstest für Decoder und Regeln über wazuh-logtest.
# Auf dem Wazuh-Manager als root ausführen; getestet wird das DEPLOYTE Ruleset.
#
#   ./tests/run-logtest.sh                 alle Fälle prüfen
#   ./tests/run-logtest.sh cases/02-*.log  einzelne Fälle prüfen
#   ./tests/run-logtest.sh --record [...]  gefeuerte IDs als Soll in die Fälle schreiben
#   ./tests/run-logtest.sh --table         tests/expected.md aus den Fällen erzeugen
#
# Ein Fall = eine Datei = eine logtest-Session. Das ist nötig, weil
# Frequency-Regeln mehrere Zeilen in derselben Session brauchen und sich
# Fälle sonst gegenseitig beeinflussen würden.
#
# Kopfzeilen eines Falls (mit # beginnend, werden nicht an logtest geschickt):
#   # desc:   Kurzbeschreibung
#   # expect: 110000 110002 110020   Menge aller Rule-IDs, die feuern müssen
#   # expect: none                   es darf keine Regel feuern
set -uo pipefail

LOGTEST="${LOGTEST:-/var/ossec/bin/wazuh-logtest}"
DIR="$(cd "$(dirname "$0")" && pwd)"

mode=check
case "${1:-}" in
  --record) mode=record; shift ;;
  --table)  mode=table;  shift ;;
esac

cases=("$@")
if [[ ${#cases[@]} -eq 0 ]]; then
  shopt -s nullglob
  cases=("$DIR"/cases/*.log)
fi
[[ ${#cases[@]} -eq 0 ]] && { echo "keine Testfälle gefunden" >&2; exit 2; }

header() {  # header <file> <key>
  sed -n "s/^# *$2: *//p" "$1" | head -n1
}

norm() {  # IDs sortiert, eindeutig, eine Zeile; "none" -> leer
  tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un | xargs
}

fired() {  # alle Rule-IDs, die in der Session gefeuert haben
  grep -vE '^[[:space:]]*(#|$)' "$1" \
    | "$LOGTEST" 2>&1 \
    | sed -n "s/^[[:space:]]*id: '\([0-9]\{1,\}\)'.*/\1/p" \
    | norm
}

if [[ $mode == table ]]; then
  out="$DIR/expected.md"
  {
    echo "# Erwartete Ergebnisse"
    echo
    echo "Erzeugt mit \`run-logtest.sh --table\` – nicht von Hand pflegen."
    echo
    echo "| Fall | Beschreibung | Zeilen | Erwartete Rule-IDs |"
    echo "|---|---|---|---|"
    for c in "${cases[@]}"; do
      [[ $(basename "$c") == 9*-local-* ]] && continue   # lokale Faelle nicht in die Tabelle
      n=$(grep -cvE '^[[:space:]]*(#|$)' "$c")
      printf '| `%s` | %s | %s | %s |\n' \
        "$(basename "$c")" "$(header "$c" desc)" "$n" "$(header "$c" expect)"
    done
  } > "$out"
  echo "geschrieben: $out"
  exit 0
fi

if [[ ! -x "$LOGTEST" ]]; then
  echo "wazuh-logtest nicht gefunden: $LOGTEST" >&2
  exit 2
fi

pass=0 fail=0 unrec=0
for c in "${cases[@]}"; do
  name=$(basename "$c")
  got=$(fired "$c")
  raw=$(header "$c" expect)

  if [[ $mode == record ]]; then
    new="# expect: ${got:-none}"
    if grep -q '^# *expect:' "$c"; then
      sed -i "0,/^# *expect:.*/s//$new/" "$c"
    else
      sed -i "1i $new" "$c"
    fi
    printf 'REC   %-40s %s\n' "$name" "${got:-none}"
    continue
  fi

  if [[ -z "$raw" || "$raw" == RECORD-ME* ]]; then
    printf 'NEU   %-40s feuert: %s\n' "$name" "${got:-none}"
    unrec=$((unrec + 1))
    continue
  fi

  want=$(echo "$raw" | norm)
  if [[ "$got" == "$want" ]]; then
    printf 'OK    %-40s %s\n' "$name" "${got:-none}"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-40s\n      soll: %s\n      ist:  %s\n' \
      "$name" "${want:-none}" "${got:-none}"
    fail=$((fail + 1))
  fi
done

[[ $mode == record ]] && { echo "Soll-Werte geschrieben – Diff prüfen, dann committen."; exit 0; }

echo
echo "$pass ok, $fail fehlgeschlagen, $unrec ohne Soll-Wert"
[[ $unrec -gt 0 ]] && echo "Soll-Werte einmalig festhalten: $0 --record <fall>"
[[ $fail -eq 0 ]]
