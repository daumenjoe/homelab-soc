# Velociraptor (Endpoint-Forensik und Hunting)

LXC `velociraptor` (.228, Debian 13), Velociraptor 0.77.2 als einzelnes Binary, Server-Konfiguration per
`config generate -i` (selbstsignierte Deployment-CA – das ist Velociraptors Sicherheitsmodell; GUI auf
8889, Frontend für Clients auf 8000). Stolperfallen: GUI `bind_address` steht nach dem Generator auf
localhost; `Client.server_urls` ebenso – beides auf den DNS-Namen setzen, sonst verbinden die Clients
nicht; `debian client --output` erwartet ein Verzeichnis. Client-Pakete für amd64 und (mit `--binary`)
arm64 für die Pis. Neun Clients: alle Linux-Systeme außer Honeypot.

**Brücke zu Wazuh ohne Integration:** Velociraptor schreibt die Ergebnisse der Client-Überwachung als
JSON-Zeilen in den Datastore (`clients/<id>/monitoring/<Artefakt>/<Quelle>/<Datum>.json`). Der Wazuh-
Agent auf dem LXC liest diese Dateien per Wildcard (`agent/servers/agent.conf`, Block `velociraptor`);
`setfacl` gibt `wazuh` Leserecht inklusive Default-ACL für neue Dateien.

**Eigenes Event-Artefakt `Homelab.Events.Baseline`** (`Homelab.Events.Baseline.yaml`, in der GUI unter
View Artifacts einspielen, dann unter Client Events für die Gruppe All aktivieren): alle 60 Sekunden (Parameter Period)
`diff()` gegen den letzten Stand für Listening-Ports, `authorized_keys`-Einträge und Cron-Zeilen; nur
Hinzugefügtes wird gemeldet, jede Zeile trägt den Hostnamen. `Linux.Events.SSHLogin` ist unbrauchbar auf
Systemen ohne `auth.log` (Ubuntu 24.04+) und ohnehin durch Wazuh abgedeckt.

**Zweites Event-Artefakt `Homelab.Events.FirewallState`** (`Homelab.Events.FirewallState.yaml`, gleicher
Einspielweg): überwacht den nftables-Ruleset als Menge von Chains, eine Zeile je `table/chain`, aus
`nft -j list ruleset`. Meldet `added` **und** `removed`, denn das Verschwinden von Chains ist hier das
Signal (`ufw disable`, `nft flush ruleset`, `iptables -X`). Chain-Menge statt Regel-Hash, weil Docker bei
jedem Container-Start Regeln innerhalb bestehender Chains ändert, aber keine Chains. Ergänzt die
auditd-Erkennung (sieht den Aufruf) um den Zustand: greift auch bei Netlink-Direktzugriff oder einem
umbenannten Binary. Wazuh-Regeln 110184 (jede Änderung, L10), 110186 (nur removed), 110185 (5+ removed
in 2 min, L12). Verifiziert mit `ufw disable` auf llm. VQL-Fallstricke beim Bau stehen in TUNING.md,
Befund 33c.

**Wazuh-Regeln** `0108-velociraptor_rules.xml` 110180–110183: neuer SSH-Key → 10, neue Cron-Zeile → 9,
neuer Listening-Port → 8 (alle nach IRIS, Gruppe `velociraptor`); `Diff=removed` bleibt stumm.
Produktiv belegt: Listener auf iris → Wazuh → IRIS-Alert in sechs Minuten.

**Hunting:** Hunt Manager → New Hunt mit `Linux.Sys.Pslist`, `Linux.Sys.Crontab` u. a. – eine Frage,
alle Antworten. Das ist die Grundlage für Atomic Red Team: sehen, was ein Angriff auf dem Host hinterlässt.
