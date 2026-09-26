# FRITZ!Box-Integration

`fritz-monitor.py` läuft alle fünf Minuten (systemd-Timer) auf dem Relay-Container und holt
Ereignisprotokoll (Web-Session, PBKDF2-Login – TR-064 `GetDeviceLog` ist auf Provider-Firmware
gesperrt), Geräteliste und Port-Freigaben (TR-064, eigener Benutzer mit Recht „FRITZ!Box Einstellungen")
sowie den WAN-Status. Nur Änderungen werden als JSON-Zeilen nach `/var/log/fritz/fritz.log` geschrieben:
neue Protokollzeilen (klassifiziert), unbekannte MAC-Adressen, hinzugefügte oder entfernte Port-Freigaben,
Wechsel der externen IP, plus Heartbeat. Der Erstlauf merkt sich den Bestand, ohne ihn zu melden; die
eigenen Anmeldungen des Monitors werden ausgeblendet (`self_ip` in der Konfiguration).
Konfiguration `/etc/fritz-monitor.json` (root, 600), State `/var/lib/fritz-monitor/state.json`.
Wazuh: Agent des Relays (Gruppe `servers`) liest die Datei, Regeln 110140–110155.
