# Monitoring (Prometheus + Grafana)

LXC `grafana` (.227, Debian 13): Prometheus aus Debian, Grafana aus dem Hersteller-Repo, HTTPS mit
Let's-Encrypt-Zertifikat vom Relay (`deploy/grafana.sh`), Wazuh-Agent in Gruppe `servers`.

**Quellen:** `prometheus.yml` – node_exporter auf allen Hosts außer Laptop und Honeypot (ufw auf
Sensor und LLM nur für .227), Pi-hole-Exporter (eko, v1.2.0, `linux-arm` auf dem 64-Bit-Pi, Pi-hole-6-
App-Passwort) auf Port 9617, Fritzbox-Exporter (sberk42, selbst gebaut mit `go install`, Benutzer `wazuh`
mit NAS/VPN-Recht, UPnP-Status in der Box aktiv, `metrics-lua_cable.json` für die 6591) auf dem Relay
Port 9042 – 243 Reihen inkl. DOCSIS-Kanäle, CPU-Temperatur, Traffic, aktive Hosts.

**Dashboards:** Node Exporter Full (1860), Pi-hole (10176), Fritzbox (sberk42-JSON aus dem Modul).

**Warum neben dem SIEM:** Wazuh beantwortet „ist etwas passiert?", Grafana „wie sieht normal aus?".
Am ersten Tag zeigte die Kurve des Backup-Rechners auf die Sekunde, wann er unter dem NFS-Backup das
Netz verlor (Befund 23).

**Offen:** Suricata-/Kismet-Statistiken, Wazuh-Indexer als Datenquelle (Alert-Volumen als Kurve),
Fritzbox-`metrics.json` auf die 6591 zuschneiden.
