# Detection Coverage (ATT&CK × Homelab)

Jede Zeile: eine Atomic-Red-Team-Technik, die erwartete Erkennung, der Sensor, das Ergebnis.
Stand wird vom Testlauf (`run-atomic.sh`) aktualisiert.

| Technik | Name | Atomic | erwartete Regel | Sensor | Ergebnis |
|---|---|---|---|---|---|
| T1053.003 | Cron persistence | 1 | 110183 | Velociraptor | ERKANNT (2026-10-04) |
| T1098.004 | SSH authorized_keys | manuell* | 110182 | Velociraptor | ERKANNT (2026-10-04) |
| T1571 | Non-standard port listener | – (nc) | 110181 | Velociraptor | offen |
| T1046 | Network service scanning | 1 | 86601/110161 | Suricata | offen |
| T1071.004 | DNS to external resolver | – (dig @8.8.8.8) | 110166 | Suricata | offen |
| T1110 | SSH brute force → honeypot | – (hydra/ncrack) | 110133/110134 | Honeypot | offen |
| T1136.001 | Create local account | 1 | 5902 (Wazuh) | auth | offen |
| T1070.002 | Clear/remove logs | 1 | 5104 (Wazuh) | auth | offen |
| T1562.004 | Disable/modify firewall | 1 | – prüfen | auth | offen |
| T1046/T1018 | Remote system discovery | 1 | 86601 | Suricata | offen |

Regel: Scan- und Lateral-Movement-Atomics NUR gegen Honeypot (.224) oder redcanary selbst, nie gegen echte Hosts.

*T1098.004-1 prüft nur Schreibrecht (schreibt denselben Inhalt zurück), legt keinen neuen Key an; daher manuell ein fremder Key eingefügt.
