#!/usr/bin/env bash
# OpenCanary-Honeypot: SSH, Telnet, HTTP, FTP, SMB-Attrappe, Portscan-Erkennung.
# Jede Beruehrung wird als JSON-Zeile nach /var/log/opencanary/opencanary.log geschrieben.
# Als root im Container ausfuehren.
set -euo pipefail
export LANG=en_US.UTF-8

python3 -m venv /opt/opencanary
/opt/opencanary/bin/pip install -q --upgrade pip
/opt/opencanary/bin/pip install -q opencanary scapy
mkdir -p /var/log/opencanary /etc/opencanaryd

cat > /etc/opencanaryd/opencanary.conf <<'JSON'
{
  "device.node_id": "canary",
  "ip.ignorelist": [],
  "logger": {
    "class": "PyLogger",
    "kwargs": {
      "formatters": { "plain": { "format": "%(message)s" } },
      "handlers": {
        "file": { "class": "logging.handlers.WatchedFileHandler", "filename": "/var/log/opencanary/opencanary.log", "formatter": "plain" }
      }
    }
  },
  "ftp.enabled": true,  "ftp.port": 21,  "ftp.banner": "FTP server ready",
  "http.enabled": true, "http.port": 80, "http.banner": "Apache/2.4.58 (Debian)", "http.skin": "nasLogin",
  "httpproxy.enabled": false,
  "ssh.enabled": true,  "ssh.port": 22,  "ssh.version": "SSH-2.0-OpenSSH_9.2p1 Debian-2",
  "telnet.enabled": true, "telnet.port": 23, "telnet.banner": "",
  "smb.enabled": false,
  "mysql.enabled": true, "mysql.port": 3306, "mysql.banner": "8.0.36-0ubuntu0.22.04.1",
  "redis.enabled": true, "redis.port": 6379,
  "vnc.enabled": true,  "vnc.port": 5900,
  "rdp.enabled": false, "sip.enabled": false, "snmp.enabled": false, "ntp.enabled": false,
  "tftp.enabled": false, "git.enabled": false, "mssql.enabled": false, "tcpbanner.enabled": false,
  "portscan.enabled": true, "portscan.logfile": "/var/log/kern.log", "portscan.synrate": 5, "portscan.nmaposrate": 5, "portscan.lorate": 3,
  "samba.enabled": false
}
JSON

cat > /etc/systemd/system/opencanary.service <<'UNIT'
[Unit]
Description=OpenCanary honeypot
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/opencanary/bin/opencanaryd --dev --uid=nobody --gid=nogroup
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=5
Environment=LANG=en_US.UTF-8
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/logrotate.d/opencanary <<'ROT'
/var/log/opencanary/opencanary.log { weekly rotate 8 compress missingok notifempty copytruncate }
ROT

chown -R nobody:nogroup /var/log/opencanary && chmod 644 /etc/opencanaryd/opencanary.conf
systemctl daemon-reload
systemctl enable --now opencanary
sleep 5
systemctl is-active opencanary
ss -tlnp | grep -E ':(21|22|23|80|3306|5900|6379) ' | awk '{print $4}' | sort -u
