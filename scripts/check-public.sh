#!/usr/bin/env bash
# Sucht vor dem ersten Push nach Dingen, die nicht öffentlich werden sollen.
# Gibt nur Hinweise aus – die Entscheidung bleibt beim Menschen.
set -uo pipefail
cd "$(dirname "$0")/.."
hits=0

scan() {  # scan <label> <regex>
  local out
  out=$(grep -rInE --exclude-dir=.git --exclude=check-public.sh -- "$2" . || true)
  if [[ -n "$out" ]]; then
    printf '\n## %s\n%s\n' "$1" "$out"
    hits=$((hits + 1))
  fi
}

scan "MAC-Adressen"          '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
scan "Mögliche Zugangsdaten" '(passw(or)?d|secret|token|api[_-]?key)[[:space:]]*[=:]'
scan "E-Mail-Adressen"       '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}'
scan "Private Schlüssel"     'BEGIN [A-Z ]*PRIVATE KEY'

echo
if [[ $hits -eq 0 ]]; then
  echo "Nichts Auffälliges gefunden."
else
  echo "$hits Kategorie(n) mit Treffern – bitte durchsehen."
fi
cat <<'EOF'

Nicht automatisch prüfbar:
- Domains in tests/cases/ und lists/dns-allow verraten Surf- und
  Geräteverhalten. Bewusst kuratieren, im Zweifel durch example.com ersetzen.
- 192.168.178.x ist Fritzbox-Standard und unkritisch; die eigene WAN-IP
  oder DynDNS-/MyFRITZ-Namen gehören nicht ins Repo.
EOF
