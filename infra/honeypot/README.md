# Honeypot (OpenCanary)

Unprivilegierter LXC mit OpenCanary im venv (`setup-canary.sh`): SSH (22), Telnet, FTP, HTTP mit
NAS-Login-Seite, Redis, VNC. Verwaltungs-SSH liegt auf 2222 (Debian 13: `ssh.socket` deaktivieren,
sonst bleibt 22 belegt). Jede Berührung wird als JSON-Zeile geloggt, der Wazuh-Agent (Gruppe `honeypot`)
liest die Datei, Regeln 110130–110135 bewerten. Login-Versuche und Brute-Force (Level 10/12) landen
in IRIS und per Mail. Niemand im Netz hat einen Grund, den Köder anzufassen – jeder Alert ist echt.
Kein SMB (braucht Samba, im unprivilegierten LXC nicht sinnvoll), keine Portscan-Erkennung (braucht
iptables-Logging im Kernel).
