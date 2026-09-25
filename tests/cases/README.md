# Testfälle

Ein Fall pro Datei, Nummernkreise wie bei den Regeln:

| Präfix | Modul |
|---|---|
| `0x`, `3x` | Pi-hole Query-Log |
| `1x` | Unbound (Zeilen 1:1 aus `/var/log/unbound/unbound.log` übernehmen – das Format hängt von `log-time-ascii` ab) |
| `2x` | pihole-analytics (JSON, eine Zeile pro Event) |
| `4x` | Hardware-Metriken des Proxmox-Hosts (JSON) |

Neuen Fall anlegen: Zeilen aus dem echten Log kopieren, Domains bei Bedarf
neutralisieren, `# desc:` setzen, dann `../run-logtest.sh --record <datei>`
und das geschriebene `# expect:` gegen die Absicht prüfen. Erst wenn Soll und
Absicht übereinstimmen, committen – sonst zementiert der Test einen Fehler.
