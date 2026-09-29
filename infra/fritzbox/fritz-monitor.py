#!/opt/fritz/bin/python3
"""FRITZ!Box -> JSON lines for Wazuh.

Sources
  - event log:     web session (login_sid.lua v2 + data.lua page=log); TR-064 GetDeviceLog is
                   blocked on provider firmware (401 despite rights)
  - hosts:         TR-064 Hosts1 (new device = unknown MAC, device went active/inactive is ignored)
  - port mappings: TR-064 WANIPConnection1 (any change is an event)
  - WAN status:    TR-064 WANIPConnection1 GetStatusInfo / GetExternalIPAddress (heartbeat)

State in /var/lib/fritz-monitor/state.json; output /var/log/fritz/fritz.log.
Config /etc/fritz-monitor.json: {"address": "192.168.178.1", "user": "...", "password": "..."}
Usage: fritz-monitor.py [--dry-run]   (dry-run prints instead of writing, keeps state untouched)
"""
import hashlib
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from fritzconnection import FritzConnection

CONFIG = "/etc/fritz-monitor.json"
STATE = Path("/var/lib/fritz-monitor/state.json")
OUT = Path("/var/log/fritz/fritz.log")
DRY = "--dry-run" in sys.argv

# Klassifikation der Protokollzeilen (Muster -> Kategorie). Reihenfolge = Priorität.
CATEGORIES = [
    (r"Anmeldung (des Benutzers .* )?an der FRITZ!Box-Benutzeroberfläche .*gescheitert", "ui_login_failed"),
    (r"Anmeldung einer App .*gescheitert", "app_login_failed"),
    (r"Anmeldung (des Benutzers .* )?an der FRITZ!Box-Benutzeroberfläche", "ui_login"),
    (r"Anmeldung einer App", "app_login"),
    (r"FRITZ!Box-Einstellungen wurden .*geändert|Einstellungen .*geändert", "settings_changed"),
    (r"WireGuard|VPN|IPSec", "vpn"),
    (r"Portfreigabe|Port-Freigabe|freigegeben", "port_forwarding"),
    (r"WLAN-Anmeldung ist gescheitert|WLAN-Gerät wurde abgewiesen|falsches Kennwort|Authentifizierungsfehler", "wlan_auth_failed"),
    (r"WLAN-Gerät (wurde )?angemeldet|Neues WLAN-Gerät", "wlan_join"),
    (r"WLAN-Gerät (wurde )?abgemeldet", "wlan_leave"),
    (r"Internetverbindung wurde getrennt|Zeitüberschreitung|Kabelverbindung .*getrennt|DOCSIS", "wan_down"),
    (r"Internetverbindung wurde erfolgreich hergestellt|erfolgreich hergestellt", "wan_up"),
    (r"Firmware|FRITZ!OS|Update", "firmware"),
    (r"Neustart|wurde neu gestartet|System gestartet", "reboot"),
    (r"DECT|Telefon|Anruf|Rufnummer|SIP|VoIP", "telephony"),
    (r"Gerät .* neu|IP-Adresse .* vergeben|DHCP", "dhcp"),
    (r"Systemzeit|NTP|Zeitserver", "time"),
]
SELF_PATTERN = None   # eigene Zugriffe des Monitors; wird in main() aus user + self_ip gebaut
COUNTER_SUFFIX = re.compile(r"\s*\[\d+ Meldungen seit .*?\]\s*$")   # Box haengt Zaehler an wiederholte Zeilen


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


def emit(events, kind, **fields):
    events.append({"fritz": {"kind": kind, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}})


# ------------------------------------------------------------------ web session (event log)
def web_login(base, user, password):
    r = requests.get(f"{base}/login_sid.lua?version=2", timeout=10)
    root = ET.fromstring(r.text)
    if root.findtext("SID", "0" * 16) != "0" * 16:
        return root.findtext("SID")
    challenge = root.findtext("Challenge", "")
    if challenge.startswith("2$"):
        _, iter1, salt1, iter2, salt2 = challenge.split("$")
        h1 = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt1), int(iter1))
        h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(salt2), int(iter2))
        response = f"{salt2}${h2.hex()}"
    else:  # legacy md5
        md5 = hashlib.md5(f"{challenge}-{password}".encode("utf-16le")).hexdigest()
        response = f"{challenge}-{md5}"
    r = requests.post(f"{base}/login_sid.lua?version=2", data={"username": user, "response": response}, timeout=10)
    sid = ET.fromstring(r.text).findtext("SID")
    if not sid or sid == "0" * 16:
        raise RuntimeError("web login failed")
    return sid


def fetch_event_log(base, sid):
    r = requests.post(f"{base}/data.lua", data={"sid": sid, "page": "log", "xhrId": "all", "lang": "de"}, timeout=15)
    r.raise_for_status()
    data = r.json().get("data", {})
    entries = data.get("log", [])
    out = []
    for e in entries:
        if isinstance(e, dict):
            out.append({"date": e.get("date", ""), "time": e.get("time", ""), "msg": e.get("msg", ""), "id": str(e.get("id", ""))})
        elif isinstance(e, (list, tuple)) and len(e) >= 3:
            out.append({"date": e[0], "time": e[1], "msg": e[2], "id": str(e[3]) if len(e) > 3 else ""})
    return out


def classify(msg):
    msg = COUNTER_SUFFIX.sub("", msg)
    if SELF_PATTERN and SELF_PATTERN.search(msg):
        return "self"
    for pattern, cat in CATEGORIES:
        if re.search(pattern, msg, re.I):
            return cat
    return "other"


# ------------------------------------------------------------------ TR-064
def tr064_hosts(fc):
    n = fc.call_action("Hosts1", "GetHostNumberOfEntries")["NewHostNumberOfEntries"]
    hosts = {}
    for i in range(n):
        try:
            h = fc.call_action("Hosts1", "GetGenericHostEntry", NewIndex=i)
        except Exception:  # noqa: BLE001
            continue
        mac = (h.get("NewMACAddress") or "").upper()
        if mac:
            hosts[mac] = {"ip": h.get("NewIPAddress", ""), "name": h.get("NewHostName", ""),
                          "active": bool(h.get("NewActive")), "iface": h.get("NewInterfaceType", "")}
    return hosts


def tr064_portmappings(fc):
    maps = []
    for i in range(64):
        try:
            m = fc.call_action("WANIPConnection1", "GetGenericPortMappingEntry", NewPortMappingIndex=i)
        except Exception:  # noqa: BLE001
            break
        maps.append({"ext_port": m.get("NewExternalPort"), "proto": m.get("NewProtocol"), "int_port": m.get("NewInternalPort"),
                     "client": m.get("NewInternalClient"), "enabled": bool(m.get("NewEnabled")), "desc": m.get("NewPortMappingDescription", "")})
    return sorted(maps, key=lambda x: (str(x["proto"]), int(x["ext_port"] or 0)))


def tr064_wan(fc):
    out = {}
    try:
        s = fc.call_action("WANIPConnection1", "GetStatusInfo")
        out.update(status=s.get("NewConnectionStatus"), uptime_s=s.get("NewUptime"), last_error=s.get("NewLastConnectionError"))
    except Exception as exc:  # noqa: BLE001
        out["status_error"] = type(exc).__name__
    try:
        out["external_ip"] = fc.call_action("WANIPConnection1", "GetExternalIPAddress")["NewExternalIPAddress"]
    except Exception as exc:  # noqa: BLE001
        out["ip_error"] = type(exc).__name__
    return out


# ------------------------------------------------------------------ main
def main():
    cfg = load_json(CONFIG, None)
    if not cfg:
        sys.exit(f"config missing: {CONFIG}")
    base = f"http://{cfg['address']}"
    global SELF_PATTERN
    if cfg.get("self_ip"):
        SELF_PATTERN = re.compile(rf"Anmeldung .*Benutzers {re.escape(cfg['user'])} .*von IP-Adresse {re.escape(cfg['self_ip'])}\.?$")
    state = load_json(STATE, {"seen_log": [], "known_macs": {}, "portmappings": None, "external_ip": None})
    events = []
    errors = {}

    # --- event log via web session
    try:
        sid = web_login(base, cfg["user"], cfg["password"])
        entries = fetch_event_log(base, sid)
        def key(e):
            return f"{e['date']} {e['time']} " + COUNTER_SUFFIX.sub("", e["msg"])
        seen = set(state["seen_log"])
        first_run = not seen
        new = [e for e in entries if key(e) not in seen]
        for e in (reversed(new) if not first_run else []):   # ältestes zuerst; Erstlauf: nur merken, nicht melden
            cat = classify(e["msg"])
            if cat == "self":
                continue
            emit(events, "log", category=cat, box_time=f"{e['date']} {e['time']}", msg=e["msg"], msg_id=e["id"])
        # alles Gesehene behalten (kein Deckel, sonst werden alte Zeilen bei jedem Lauf wieder "neu")
        state["seen_log"] = sorted(seen | {key(e) for e in entries})[-20000:]
        try:
            requests.get(f"{base}/login_sid.lua?version=2&logout=1&sid={sid}", timeout=5)
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        errors["log"] = f"{type(exc).__name__}: {exc}"[:160]

    # --- TR-064
    try:
        fc = FritzConnection(address=cfg["address"], user=cfg["user"], password=cfg["password"], timeout=15)
        hosts = tr064_hosts(fc)
        known = state["known_macs"]
        first_hosts_run = not known
        for mac, h in hosts.items():
            if mac not in known:
                if not first_hosts_run:
                    emit(events, "new_device", mac=mac, ip=h["ip"], name=h["name"], iface=h["iface"], active=h["active"])
                known[mac] = {"first_seen": time.strftime("%Y-%m-%d"), "name": h["name"]}
        state["known_macs"] = known

        maps = tr064_portmappings(fc)
        if state["portmappings"] is not None and maps != state["portmappings"]:
            before = {json.dumps(m, sort_keys=True) for m in state["portmappings"]}
            after = {json.dumps(m, sort_keys=True) for m in maps}
            for m in after - before:
                emit(events, "port_forwarding", change="added", **json.loads(m))
            for m in before - after:
                emit(events, "port_forwarding", change="removed", **json.loads(m))
        state["portmappings"] = maps

        wan = tr064_wan(fc)
        if state["external_ip"] and wan.get("external_ip") and wan["external_ip"] != state["external_ip"]:
            emit(events, "wan_ip_changed", old=state["external_ip"], new=wan["external_ip"])
        state["external_ip"] = wan.get("external_ip") or state["external_ip"]
        emit(events, "heartbeat", hosts_total=len(hosts), hosts_active=sum(1 for h in hosts.values() if h["active"]),
             portmappings=len(maps), wan=wan, errors=errors or None)
    except Exception as exc:  # noqa: BLE001
        errors["tr064"] = f"{type(exc).__name__}: {exc}"[:160]
        emit(events, "heartbeat", errors=errors)

    if DRY:
        for e in events:
            print(json.dumps(e, ensure_ascii=False))
        print(f"-- {len(events)} events, state not saved", file=sys.stderr)
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state), encoding="utf-8")


if __name__ == "__main__":
    main()
