#!/usr/bin/env python3
"""Homelab watchdog - runs OUTSIDE the detection chain and tells you when the chain itself is down.

Checks (every run): HTTPS endpoints, DNS via Pi-hole, ping of core hosts, Wazuh API agent status,
internet reachability. Notifies via ntfy only on state changes (down -> up, up -> down), plus one
daily heartbeat so you notice when the watchdog itself goes quiet.

Config: /etc/watchdog.json   State: /var/lib/homelab-watchdog/state.json
Usage:  watchdog.py [--dry-run]   (dry-run prints results, sends nothing, keeps state)
"""
import json
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG = Path("/etc/watchdog.json")
STATE = Path("/var/lib/homelab-watchdog/state.json")
DRY = "--dry-run" in sys.argv


def load(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


# ------------------------------------------------------------------ checks: each returns (ok, detail)
def check_https(url, verify=True, expect=(200, 301, 302, 401, 403)):
    try:
        r = requests.get(url, timeout=8, verify=verify, allow_redirects=False)
        return r.status_code in expect, f"HTTP {r.status_code}"
    except Exception as exc:  # noqa: BLE001
        return False, type(exc).__name__


def check_ping(host):
    r = subprocess.run(["ping", "-c", "2", "-W", "2", host], capture_output=True)
    return r.returncode == 0, "reply" if r.returncode == 0 else "no reply"


def check_dns(server, name):
    r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", f"@{server}", name], capture_output=True, text=True)
    ok = r.returncode == 0 and r.stdout.strip() != ""
    return ok, r.stdout.strip().split("\n")[0] if ok else "no answer"


def check_wazuh_agents(api, user, password, verify):
    """Return (ok, detail) with the list of agents that are not active."""
    try:
        tok = requests.post(f"{api}/security/user/authenticate", auth=(user, password), verify=verify, timeout=8)
        tok.raise_for_status()
        headers = {"Authorization": f"Bearer {tok.json()['data']['token']}"}
        r = requests.get(f"{api}/agents", headers=headers, verify=verify, timeout=8,
                         params={"select": "name,status", "limit": 100})
        r.raise_for_status()
        agents = [a for a in r.json()["data"]["affected_items"] if a.get("name") != "wazuh-manager" and a.get("id") != "000"]
        bad = sorted(a["name"] for a in agents if a.get("status") != "active")
        return not bad, f"{len(agents) - len(bad)}/{len(agents)} active" + (f", down: {', '.join(bad)}" if bad else "")
    except Exception as exc:  # noqa: BLE001
        return False, f"API {type(exc).__name__}"


def check_pve_backups(cfg):
    """Newest backup per storage must be younger than its allowed age (hours)."""
    pb = cfg['pve_backup']
    headers = {'Authorization': f"PVEAPIToken={pb['token']}"}
    out, ok_all = [], True
    for storage, max_h in pb['storages'].items():
        try:
            r = requests.get(f"{pb['url']}/api2/json/nodes/{pb['node']}/storage/{storage}/content",
                             headers=headers, params={'content': 'backup'}, verify=pb.get('verify', True), timeout=10)
            r.raise_for_status()
            newest = max((c.get('ctime', 0) for c in r.json()['data']), default=0)
            age_h = (time.time() - newest) / 3600 if newest else 9e9
            ok = age_h <= max_h
            out.append(f"{storage} {'none' if not newest else f'{age_h:.0f}h'}" + ('' if ok else f' (>{max_h}h)'))
        except Exception as exc:  # noqa: BLE001
            ok = False; out.append(f"{storage} {type(exc).__name__}")
        ok_all = ok_all and ok
    return ok_all, ', '.join(out)


# ------------------------------------------------------------------ notify
def notify(cfg, title, message, priority="default", tags=""):
    if DRY:
        print(f"[ntfy] {title}: {message}")
        return
    try:
        requests.post(cfg["ntfy_url"], data=message.encode("utf-8"), timeout=10,
                      headers={"Title": title, "Priority": priority, "Tags": tags})
    except Exception as exc:  # noqa: BLE001
        print(f"ntfy failed: {exc}", file=sys.stderr)


# ------------------------------------------------------------------ main
def main():
    cfg = load(CONFIG, None)
    if not cfg:
        sys.exit(f"config missing: {CONFIG}")
    state = load(STATE, {"status": {}, "last_heartbeat": ""})
    results = {}

    internet_ok, _ = check_ping(cfg.get("internet_probe", "1.1.1.1"))
    results["internet"] = (internet_ok, "reply" if internet_ok else "no reply")
    for name, url in cfg.get("https", {}).items():
        results[f"https:{name}"] = check_https(url, verify=cfg.get("verify_tls", True))
    for name, host in cfg.get("ping", {}).items():
        results[f"ping:{name}"] = check_ping(host)
    for name, (server, qname) in cfg.get("dns", {}).items():
        results[f"dns:{name}"] = check_dns(server, qname)
    if cfg.get("wazuh_api"):
        w = cfg["wazuh_api"]
        results["wazuh:agents"] = check_wazuh_agents(w["url"], w["user"], w["password"], w.get("verify", cfg.get("verify_tls", True)))

    if cfg.get('pve_backup'):
        results['pve:backups'] = check_pve_backups(cfg)

    # state transitions
    old = state["status"]
    went_down = [k for k, (ok, _) in results.items() if not ok and old.get(k, True)]
    came_back = [k for k, (ok, _) in results.items() if ok and old.get(k) is False]
    still_down = [k for k, (ok, _) in results.items() if not ok and old.get(k) is False]

    if went_down:
        body = "\n".join(f"{k}: {results[k][1]}" for k in went_down)
        if not internet_ok:
            body = "Internet unreachable - everything below may be a side effect\n" + body
        notify(cfg, f"DOWN: {', '.join(went_down)}", body, priority="high", tags="rotating_light")
    if came_back:
        notify(cfg, f"UP again: {', '.join(came_back)}", "\n".join(f"{k}: {results[k][1]}" for k in came_back), tags="white_check_mark")

    # daily heartbeat
    today = datetime.now().strftime("%Y-%m-%d")
    hour = datetime.now().hour
    if state.get("last_heartbeat") != today and hour >= cfg.get("heartbeat_hour", 8):
        n_ok = sum(1 for ok, _ in results.values() if ok)
        down = ", ".join(still_down + went_down) or "none"
        notify(cfg, f"Watchdog: {n_ok}/{len(results)} checks ok", f"down: {down}\nwazuh: {results.get('wazuh:agents', ('', '-'))[1]}", tags="heartbeat")
        state["last_heartbeat"] = today

    for k, (ok, detail) in sorted(results.items()):
        print(f"{'OK ' if ok else 'BAD'} {k:24} {detail}")
    if not DRY:
        state["status"] = {k: ok for k, (ok, _) in results.items()}
        state["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
