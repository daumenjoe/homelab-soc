#!/usr/bin/env python3
"""Keep Suricata's HOME_NET in sync with the IPv6 prefixes the router advertises.

The provider assigns the global IPv6 prefix dynamically. Instead of asking the router, listen on the
mirror interface for the next Router Advertisement (the router sends one every few minutes), read the
prefix options (global + ULA), and rewrite HOME_NET in suricata.yaml. Suricata is restarted only when
the value actually changed. Static parts (IPv4 LAN, link-local) are always included.

Usage: suricata-homenet.py [--iface eth0] [--timeout 600] [--dry-run]
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

YAML = Path("/etc/suricata/suricata.yaml")
STATIC = ["192.168.178.0/24", "fe80::/10"]
STATE = Path("/var/lib/suricata/homenet.last")


def ra_prefixes(iface, timeout):
    """Capture one Router Advertisement and return its prefix options (CIDR strings)."""
    cmd = ["timeout", str(timeout), "tcpdump", "-ni", iface, "-v", "-c", "1", "icmp6 and ip6[40] == 134"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return sorted(set(re.findall(r"prefix info option.*?: ([0-9a-f:]+/\d+)", out)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    prefixes = ra_prefixes(a.iface, a.timeout)
    if not prefixes:
        sys.exit("no router advertisement seen - HOME_NET left unchanged")
    home_net = ",".join(STATIC[:1] + prefixes + STATIC[1:])
    line = f'    HOME_NET: "[{home_net}]"'

    yaml = YAML.read_text(encoding="utf-8")
    m = re.search(r"^    HOME_NET: .*$", yaml, re.M)
    if not m:
        sys.exit("HOME_NET line not found in suricata.yaml")
    changed = m.group(0) != line
    print(f"prefixes: {prefixes} | changed: {changed}")
    if a.dry_run or not changed:
        return
    YAML.write_text(yaml[:m.start()] + line + yaml[m.end():], encoding="utf-8")
    if subprocess.run(["suricata", "-T", "-c", str(YAML)], capture_output=True).returncode != 0:
        YAML.write_text(yaml, encoding="utf-8")   # roll back
        sys.exit("config test failed after HOME_NET change - rolled back")
    subprocess.run(["systemctl", "restart", "suricata"], check=False)
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(home_net + "\n", encoding="utf-8")
    print(f"HOME_NET updated: [{home_net}]")


if __name__ == "__main__":
    main()
