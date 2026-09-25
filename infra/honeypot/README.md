# Honeypot (OpenCanary)

Unprivilegierter LXC mit OpenCanary im venv (`setup-canary.sh`): SSH (22), Telnet, FTP, HTTP mit
NAS-Login-Seite, Redis, VNC. Verwaltungs-SSH liegt auf 2222 (Debian 13: `ssh.socket` deaktivieren,
sonst bleibt 22 belegt). Jede Berührung wird als JSON-Zeile geloggt, der Wazuh-Agent (Gruppe `honeypot`)
liest die Datei, Regeln 110130–110135 bewerten. Login-Versuche und Brute-Force (Level 10/12) landen
in IRIS und per Mail. Niemand im Netz hat einen Grund, den Köder anzufassen – jeder Alert ist echt.
Kein SMB (braucht Samba, im unprivilegierten LXC nicht sinnvoll), keine Portscan-Erkennung (braucht
iptables-Logging im Kernel).

## Härtung

OpenCanary gibt nach dem Binden der Ports die Rechte ab (`--uid=nobody --gid=nogroup`, `CAP_NET_BIND_SERVICE`). Die Proxmox-Firewall des Containers lässt eingehend alles zu (Köder) und ausgehend nur den Wazuh-Manager (1514/1515) und DNS – ein übernommener Köder kann nirgendwohin. Für Updates die Container-Firewall kurz deaktivieren. Der Honeypot ist nur im LAN erreichbar; Internet-Exposition würde eigene Schwellen, ein eigenes Netzsegment und weitere Härtung brauchen.
