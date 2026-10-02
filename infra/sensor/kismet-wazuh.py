#!/usr/bin/env python3
"""Kismet -> JSON lines for Wazuh.

Polls the Kismet REST API for alerts and newly seen devices since the last run and appends them as
one JSON object per line to /var/log/kismet/kismet-wazuh.json. Adds a heartbeat with counts.

Config: /etc/kismet-wazuh.json  {"url": "http://127.0.0.1:2501", "api_key": "...",
                                 "own_bssids": ["74:42:7F:..."], "own_ssids": ["..."]}
State:  /var/lib/kismet-wazuh/state.json
Usage:  kismet-wazuh.py [--dry-run]
"""
import json
import sys
import time
from pathlib import Path

import requests

CONFIG = Path("/etc/kismet-wazuh.json")
STATE = Path("/var/lib/kismet-wazuh/state.json")
OUT = Path("/var/log/kismet/kismet-wazuh.json")
DRY = "--dry-run" in sys.argv


def load(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


def get(cfg, path):
    r = requests.get(cfg["url"].rstrip("/") + path, headers={"Cookie": f"KISMET={cfg['api_key']}"}, timeout=20)
    r.raise_for_status()
    return r.json()


def emit(events, kind, **fields):
    events.append({"kismet": {"kind": kind, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}})


def main():
    cfg = load(CONFIG, None)
    if not cfg:
        sys.exit(f"config missing: {CONFIG}")
    own_bssids = {m.lower() for m in cfg.get("own_bssids", [])}
    own_ssids = set(cfg.get("own_ssids", []))
    now = int(time.time())
    state = load(STATE, {"last_alert_ts": now - 120, "last_device_ts": now - 120, "known_macs": []})
    known = set(state["known_macs"])
    first_run = not known
    events = []
    errors = {}

    # --- alerts since last run
    try:
        alerts = get(cfg, f"/alerts/last-time/{state['last_alert_ts']}/alerts.json")
        for a in alerts:
            emit(events, "alert",
                 header=a.get("kismet.alert.header"), severity=a.get("kismet.alert.severity"),
                 text=(a.get("kismet.alert.text") or "")[:300], channel=a.get("kismet.alert.channel"),
                 source_mac=a.get("kismet.alert.source_mac"), dest_mac=a.get("kismet.alert.dest_mac"),
                 transmitter_mac=a.get("kismet.alert.transmitter_mac"))
        state["last_alert_ts"] = now
    except Exception as exc:  # noqa: BLE001
        errors["alerts"] = type(exc).__name__

    # --- devices first seen since last run
    try:
        devices = get(cfg, f"/devices/last-time/{state['last_device_ts']}/devices.json")
        n_new = 0
        for d in devices:
            mac = (d.get("kismet.device.base.macaddr") or "").lower()
            if not mac or mac in known:
                continue
            known.add(mac)
            if first_run:
                continue   # Erstlauf: Bestand nur merken
            n_new += 1
            d11 = d.get("dot11.device", {}) or {}
            ssid = ((d11.get("dot11.device.last_beaconed_ssid_record") or {}).get("dot11.advertisedssid.ssid")
                    or (d11.get("dot11.device.last_probed_ssid_record") or {}).get("dot11.probedssid.ssid") or "")
            bssid = (d11.get("dot11.device.last_bssid") or "").lower()
            emit(events, "new_device",
                 type=d.get("kismet.device.base.type"), mac=mac, manuf=d.get("kismet.device.base.manuf"),
                 ssid=ssid, bssid=bssid, channel=d.get("kismet.device.base.channel"),
                 signal=(d.get("kismet.device.base.signal") or {}).get("kismet.common.signal.last_signal"),
                 on_own_ap=bssid in own_bssids, own_ssid=ssid in own_ssids)
        state["last_device_ts"] = now
    except Exception as exc:  # noqa: BLE001
        errors["devices"] = type(exc).__name__

    # --- heartbeat
    try:
        status = get(cfg, "/system/status.json")
        emit(events, "heartbeat", devices_known=len(known), new_devices=n_new if not first_run else 0,
             alerts=sum(1 for e in events if e["kismet"]["kind"] == "alert"),
             packets=status.get("kismet.system.packets.rrd", {}).get("kismet.common.rrd.last_value"),
             uptime_s=now - int(status.get("kismet.system.timestamp.start_sec", now)), errors=errors or None)
    except Exception as exc:  # noqa: BLE001
        emit(events, "heartbeat", devices_known=len(known), errors=dict(errors, status=type(exc).__name__))

    state["known_macs"] = sorted(known)[-20000:]
    if DRY:
        for e in events:
            print(json.dumps(e, ensure_ascii=False)[:220])
        print(f"-- {len(events)} events, state not saved (first_run={first_run})", file=sys.stderr)
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state), encoding="utf-8")


if __name__ == "__main__":
    main()
