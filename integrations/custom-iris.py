#!/var/ossec/framework/python/bin/python3
"""Wazuh custom integration: forward alerts to DFIR-IRIS as IRIS alerts, enriched.

Called by wazuh-integratord as:  custom-iris <alert_file> <api_key> <hook_url>

Enrichment (best-effort, short timeouts; a failure never blocks the alert):
  - RDAP:        registration date -> domain age in days      (no key needed)
  - VirusTotal:  last_analysis_stats, categories, reputation  (free API key)
  - Reverse DNS: PTR of the internal client -> device name    (via Pi-hole / router)

Optional config /var/ossec/etc/custom-iris.json (root:wazuh 640):
  {"customer_id": 2, "vt_api_key": "...", "dashboard_url": "https://wazuh.example",
   "verify_tls": true, "nrd_days": 30, "vt_per_minute": 4, "vt_per_day": 500}

Manual quota check (uses one request):  custom-iris --vt-quota

Install: /var/ossec/integrations/custom-iris  (root:wazuh, 0750)
Log:     /var/ossec/logs/integrations.log
"""
import fcntl
import json
import logging
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

VERSION = "2.1"
CONFIG_PATH = "/var/ossec/etc/custom-iris.json"
DEFAULTS = {"customer_id": 2, "vt_api_key": "", "dashboard_url": "https://wazuh.provinglab.de/app/wazuh",
            "verify_tls": True, "nrd_days": 30, "vt_per_minute": 4, "vt_per_day": 500}
VT_STATE = "/var/ossec/var/custom-iris-vt.json"   # local request counter, shared by parallel runs
TIMEOUT = 15
ENRICH_TIMEOUT = 8
LOG = "/var/ossec/logs/integrations.log"

logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s custom-iris: %(message)s")


def load_config():
    cfg = dict(DEFAULTS)
    try:
        cfg.update(json.loads(Path(CONFIG_PATH).read_text(encoding="utf-8")))
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        logging.warning("config %s ignored: %s", CONFIG_PATH, exc)
    return cfg


def field(d, path, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


# IRIS severity ids: 1 Unspecified, 2 Informational, 3 Low, 4 Medium, 5 High, 6 Critical
def severity(level):
    if level >= 12:
        return 6
    if level >= 10:
        return 5
    if level >= 7:
        return 4
    return 3


# --------------------------------------------------------------------------- enrichment
def enrich_rdap(regdom, nrd_days):
    """Domain age from RDAP (rdap.org redirects to the responsible registry)."""
    out = {}
    try:
        r = requests.get(f"https://rdap.org/domain/{regdom}", timeout=ENRICH_TIMEOUT,
                         headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"rdap": f"HTTP {r.status_code}"}
        data = r.json()
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - reg).days
                out.update(registered=reg.date().isoformat(), age_days=age, newly_registered=age <= nrd_days)
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for v in ent.get("vcardArray", [[], []])[1]:
                    if v[0] == "fn":
                        out["registrar"] = v[3]
        return out or {"rdap": "no registration event"}
    except Exception as exc:  # noqa: BLE001
        return {"rdap": f"error: {type(exc).__name__}"}


class VtQuota:
    """Local request budget for the VirusTotal free tier. One JSON file, locked while
    updated, so parallel integration runs cannot overspend. Never calls the API."""

    def __init__(self, path, per_minute, per_day):
        self.path, self.per_minute, self.per_day = Path(path), per_minute, per_day

    def _load(self, fh):
        try:
            fh.seek(0)
            return json.loads(fh.read() or "{}")
        except Exception:  # noqa: BLE001
            return {}

    def take(self):
        """Reserve one request. Returns None if allowed, else the reason to skip."""
        now = int(time.time())
        minute, day = now // 60, time.strftime("%Y-%m-%d", time.gmtime(now))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            st = self._load(fh)
            if st.get("blocked_until", 0) > now:
                return f"quota exhausted (HTTP 429), retry after {time.strftime('%H:%M UTC', time.gmtime(st['blocked_until']))}"
            if st.get("minute") != minute:
                st.update(minute=minute, minute_count=0)
            if st.get("day") != day:
                st.update(day=day, day_count=0)
            if st["minute_count"] >= self.per_minute:
                return f"local budget: {self.per_minute}/min reached"
            if st["day_count"] >= self.per_day:
                return f"local budget: {self.per_day}/day reached"
            st["minute_count"] += 1
            st["day_count"] += 1
            fh.seek(0); fh.truncate(); fh.write(json.dumps(st))
        return None

    def block_until_tomorrow(self):
        with open(self.path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            st = self._load(fh)
            st["blocked_until"] = (int(time.time()) // 86400 + 1) * 86400
            fh.seek(0); fh.truncate(); fh.write(json.dumps(st))

    def sync(self, used_today):
        with open(self.path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            st = self._load(fh)
            st.update(day=time.strftime("%Y-%m-%d", time.gmtime()), day_count=used_today)
            fh.seek(0); fh.truncate(); fh.write(json.dumps(st))


def vt_quota_report(api_key):
    """Ask VirusTotal for the real usage (costs one request) and sync the local counter."""
    r = requests.get(f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas",
                     headers={"x-apikey": api_key}, timeout=ENRICH_TIMEOUT)
    r.raise_for_status()
    q = r.json().get("data", {})
    out = {}
    for name in ("api_requests_hourly", "api_requests_daily", "api_requests_monthly"):
        u = q.get(name, {}).get("user", {})
        out[name.replace("api_requests_", "")] = f"{u.get('used', '?')}/{u.get('allowed', '?')}"
    return out, q.get("api_requests_daily", {}).get("user", {}).get("used")


def enrich_virustotal(regdom, api_key, quota):
    if not api_key:
        return {"virustotal": "no api key configured"}
    reason = quota.take()
    if reason:
        return {"virustotal": f"skipped: {reason}"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{regdom}",
                         headers={"x-apikey": api_key}, timeout=ENRICH_TIMEOUT)
        if r.status_code == 404:
            return {"virustotal": "unknown to VirusTotal"}
        if r.status_code == 429:
            quota.block_until_tomorrow()
            return {"virustotal": "quota exceeded (HTTP 429), paused until tomorrow"}
        if r.status_code != 200:
            return {"virustotal": f"HTTP {r.status_code}"}
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "engines": sum(stats.values()) if stats else 0,
            "reputation": a.get("reputation"),
            "categories": sorted(set(a.get("categories", {}).values()))[:5],
            "link": f"https://www.virustotal.com/gui/domain/{regdom}",
        }
    except Exception as exc:  # noqa: BLE001
        return {"virustotal": f"error: {type(exc).__name__}"}


def enrich_client(ip):
    try:
        socket.setdefaulttimeout(3)
        return {"hostname": socket.gethostbyaddr(ip)[0]}
    except Exception:  # noqa: BLE001
        return {"hostname": ""}


# --------------------------------------------------------------------------- IRIS helpers
def iris_get(base, headers, path, verify):
    r = requests.get(f"{base}{path}", headers=headers, verify=verify, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json().get("data", [])


def ioc_type_ids(base, headers, verify):
    return {t["type_name"]: t["type_id"] for t in iris_get(base, headers, "/manage/ioc-types/list", verify)}


def alert_status_id(base, headers, verify):
    try:
        for s in iris_get(base, headers, "/manage/alert-status/list", verify):
            if s.get("status_name", "").lower() == "new":
                return s["status_id"]
    except Exception:  # noqa: BLE001
        pass
    return 2


# --------------------------------------------------------------------------- build
def build_alert(alert, cfg, types, status_id):
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))
    data = alert.get("data", {})
    pa = data.get("pihole_analytics", {})

    domain = pa.get("registrable") or pa.get("domain") or field(data, "dns.domain")
    regdom = pa.get("registrable") or domain
    client = pa.get("client") or data.get("srcip") or field(data, "dns.client") or data.get("src_host")
    agent = field(alert, "agent.name", "manager")

    enrichment, tags, sev = {}, [], severity(level)
    if regdom and not regdom.endswith((".example", ".test", ".invalid", ".local", ".arpa")):
        enrichment["rdap"] = enrich_rdap(regdom, cfg["nrd_days"])
        enrichment["virustotal"] = enrich_virustotal(
            regdom, cfg["vt_api_key"], VtQuota(VT_STATE, cfg["vt_per_minute"], cfg["vt_per_day"]))
        if enrichment["rdap"].get("newly_registered"):
            tags.append("nrd")
        vt_mal = enrichment["virustotal"].get("malicious", 0)
        if vt_mal >= 1:
            tags.append("vt-flagged")
        if vt_mal >= 3 and sev < 6:
            sev += 1                      # several engines agree: one step up
    hostname = ""
    if client:
        hostname = enrich_client(client)["hostname"]
        enrichment["client"] = {"ip": client, "hostname": hostname or "no PTR"}

    summary = []
    rd, vt = enrichment.get("rdap", {}), enrichment.get("virustotal", {})
    if "age_days" in rd:
        summary.append(f"domain age {rd['age_days']} d" + (" (NRD)" if rd.get("newly_registered") else ""))
    if "malicious" in vt:
        summary.append(f"VirusTotal {vt['malicious']}/{vt['engines']} malicious")
    if hostname:
        summary.append(f"client {hostname}")

    iocs = []
    if domain and "domain" in types:
        iocs.append({"ioc_value": domain, "ioc_type_id": types["domain"], "ioc_tlp_id": 2,
                     "ioc_description": "; ".join(summary) or f"from Wazuh rule {rule.get('id')}",
                     "ioc_tags": ",".join(["dns"] + tags)})
    if client and "ip-src" in types:
        iocs.append({"ioc_value": client, "ioc_type_id": types["ip-src"], "ioc_tlp_id": 2,
                     "ioc_description": f"internal client {hostname}".strip(), "ioc_tags": "client"})

    ts = alert.get("timestamp", "")
    try:
        event_time = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        event_time = event_time.strftime("%Y-%m-%dT%H:%M:%S.000")
    except ValueError:
        event_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    description = rule.get("description", "")
    if summary:
        description += "\n\nEnrichment: " + "; ".join(summary)

    context = {
        "wazuh_rule_id": rule.get("id"), "wazuh_level": level,
        "wazuh_groups": rule.get("groups", []), "mitre": field(rule, "mitre.id", []),
        "agent": agent, "client": client, "domain": domain, "registrable": regdom,
        "enrichment": enrichment,
    }
    if pa:
        context["pihole_analytics"] = pa

    return {
        "alert_title": f"[Wazuh {rule.get('id')}] {rule.get('description', 'alert')[:180]}",
        "alert_description": description,
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id", ""),
        "alert_source_link": cfg["dashboard_url"],
        "alert_source_event_time": event_time,
        "alert_severity_id": sev,
        "alert_status_id": status_id,
        "alert_customer_id": cfg["customer_id"],
        "alert_tags": ",".join(["wazuh", "honeypot" if str(rule.get("id", "")).startswith("1101") else "dns"] + [g for g in rule.get("groups", []) if g.startswith("dns_")] + tags),
        "alert_iocs": iocs,
        "alert_context": context,
        "alert_source_content": alert,
    }


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--vt-quota":
        cfg = load_config()
        if not cfg["vt_api_key"]:
            print("no vt_api_key in", CONFIG_PATH); return 2
        report, used = vt_quota_report(cfg["vt_api_key"])
        if used is not None:
            VtQuota(VT_STATE, cfg["vt_per_minute"], cfg["vt_per_day"]).sync(used)
        for k, v in report.items():
            print(f"{k:8} {v}")
        return 0
    if len(sys.argv) < 4:
        logging.error("usage: custom-iris <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, api_key, base = sys.argv[1], sys.argv[2], sys.argv[3].rstrip("/")
    cfg = load_config()
    verify = bool(cfg["verify_tls"])
    if not verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    with open(alert_file, encoding="utf-8") as fh:
        alert = json.loads(fh.read().strip().splitlines()[-1])

    try:
        types = ioc_type_ids(base, headers, verify)
        payload = build_alert(alert, cfg, types, alert_status_id(base, headers, verify))
        r = requests.post(f"{base}/alerts/add", headers=headers, json=payload, verify=verify, timeout=TIMEOUT)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code == 200 and body.get("status") == "success":
            extra = ", ".join(payload["alert_tags"].split(",")[2:]) or "no tags"
            logging.info("rule %s -> IRIS alert %s (%s)", field(alert, "rule.id"), field(body, "data.alert_id"), extra)
            return 0
        logging.error("rule %s -> HTTP %s: %s", field(alert, "rule.id"), r.status_code, r.text[:300])
        return 1
    except Exception as exc:  # noqa: BLE001
        logging.error("rule %s -> %s", field(alert, "rule.id"), exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
