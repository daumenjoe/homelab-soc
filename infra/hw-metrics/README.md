# Hardware-Überwachung des Proxmox-Hosts

`hw-metrics.py` liest alle fünf Minuten (systemd-Timer) CPU-Temperatur (`lm-sensors`), NVMe-SMART
(`smartctl -j`), Load und Füllstand des Root-Dateisystems und schreibt eine JSON-Zeile nach
`/var/log/hw-metrics/hw-metrics.log`. Der Wazuh-Agent liest die Datei (`agent/proxmox/agent.conf`,
`log_format json`), die Regeln 110100–110111 bewerten die Werte; Schwellen orientieren sich an den
Herstellergrenzen der Sensoren (Package high 84 °C). Level ≥ 10 geht per Mail raus.

Installation auf dem Host: `apt install lm-sensors smartmontools`, `sensors-detect --auto`, Skript
nach `/usr/local/bin/`, Units nach `/etc/systemd/system/`, `systemctl enable --now hw-metrics.timer`.
