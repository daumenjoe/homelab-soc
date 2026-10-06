## Befund 32 — Velociraptor erreichte das SIEM nie (tote Brücke)

**Symptom:** Beim Volumen-Review nach dem Sensor-Umbau fiel auf, dass die
Velociraptor-Regeln 110180–110183 im Alert-Log nicht vorkamen — nicht mit
Treffer 0, sondern komplett abwesend. Die Erkennungen (neue Ports/Keys/Cron)
waren nur in der Velociraptor-GUI sichtbar.

**Diagnose (Quelle → Senke):**
- Regel-IDs 110180–110183: 0 Alerts, je.
- String-Suche "velociraptor" fand 54 Treffer → Fehlspur, waren PAM-Logins des
  velociraptor-Dienstusers (5501/5502). Lehre: auf Regel-IDs filtern, nicht auf
  frei assoziierte Strings.
- Kein `<localfile>` des Managers verweist auf Velociraptor. Es gab keinen Kanal.
- Datastore enthielt die Ergebnisse sehr wohl (inkl. Cron-Testzeile aus Runde 1,
  04.10. 14:07). Sensor arbeitete, Ergebnisse wurden nie abgeholt.

**Zweite, unabhängige Ursache:** Basis-Regel 110180 stand auf `level="0"` →
Wazuh verwirft die Regel, `if_sid`-Kinder greifen nie. Selbst mit Brücke hätte
nichts gefeuert.

**Fix:**
1. `<localfile>` (json) auf dem Velociraptor-Host (.228), liest
   `/var/lib/velociraptor/clients/*/monitoring/Homelab.Events.Baseline/*/*.json`,
   geht über den bestehenden Agent-Kanal zum Manager. Wichtig: Resultat-Baum
   `monitoring/` (nicht `monitoring_logs/` = nur Betriebsmeldungen).
2. 110180 level 0 → 2.

**Verifikation:** Test-Port 8111 auf iris → Diff → Datastore → Agent → Manager
→ Alert 110181 (L8) im alerts.json. Erster End-to-End-Durchlauf.

**Nebenbefund:** Artefakt-Beschreibung sagt "alle 5 Min", Period ist 60s
(Doku-Fix offen). Nur 7 von 9 Clients liefern Baseline-Listeners-Daten (welche
zwei fehlen, prüfen).

---

## Befund 33 — Wazuh-Regel-Ladereihenfolge bricht if_sid-Anchoring

**Symptom:** Neue auditd-Regel 110190 (Firewall-Manipulation, T1562.004) griff
live nicht, obwohl alle Felder korrekt dekodiert ankamen (per archives.json mit
testweise aktivem `logall_json` bewiesen: `audit.key=fw_tamper`, `exe`, `auid`,
`execve.a1` — alles da). logtest warnte "Signature ID 80700 not found in if_sid".

**Ursache:** Die Custom-Regeldatei hatte Präfix `0110` und lud damit *vor* der
Standard-auditd-Regeldatei `0365-auditd_rules.xml`. Die Parent-Regel 80700
("Audit: Messages grouped", level 0, in 0365) war zum Parse-Zeitpunkt von 0110
noch unbekannt → `if_sid 80700` ins Leere → Regel ignoriert.

**Fehlspuren ausgeschlossen:**
- Transport: Event kam vollständig dekodiert an (nicht das Problem).
- `decoded_as auditd` statt if_sid: löst die Warnung, aber verliert live gegen
  die grouping-Regel 80700 auf gleicher Ebene → kein Alert.

**Fix:** Regeldatei umbenannt `0110-` → `0910-defense_evasion_rules.xml`
(lädt nach 0365, 80700 ist dann bekannt).

**Verifikation (live, nicht nur logtest):** `nft list ruleset` → 110190 L7;
`nft flush ruleset` → 110191 L12 mit `a1=flush`. Zweistufige Erkennung bestätigt.

**Lehren:**
- Regeldatei-Nummerierung ist nicht nur Kosmetik — sie bestimmt, welche Parents
  via if_sid sichtbar sind. Custom-Regeln, die auf Standard-Regeln ankern,
  brauchen eine Nummer > der Standard-Datei.
- logtest ≠ Live-Daemon. logtest lädt in anderer Reihenfolge; "not found"-
  Warnungen am Live-Verhalten gegenprüfen.
- Level-0-Regeln erscheinen nie in alerts.json (nur als Parent nutzbar). Für
  Transport-Tests `logall_json` nutzen (danach WIEDER AUS — Platte).
