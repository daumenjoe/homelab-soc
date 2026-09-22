#!/var/ossec/framework/python/bin/python3
"""Wazuh custom integration: forward alerts to DFIR-IRIS as IRIS alerts.

Called by wazuh-integratord as:  custom-iris <alert_file> <api_key> <hook_url>
(the same three arguments Wazuh passes to every custom-* integration).

Install: /var/ossec/integrations/custom-iris  (root:wazuh, 0750), see README.
Log:     /var/ossec/logs/integrations.log
"""
import json
import logging
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CUSTOMER_ID = 2          # IRIS: Manage -> Customers ("HomeLab")
VERIFY_TLS = False       # self-signed IRIS certificate in the lab
TIMEOUT = 15
LOG = "/var/ossec/logs/integrations.log"

# IRIS severity ids: 1 Unspecified, 2 Informational, 3 Low, 4 Medium, 5 High, 6 Critical
def severity(level):
    if level >= 12:
        return 6
    if level >= 10:
        return 5
    if level >= 7:
        return 4
    return 3

logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s custom-iris: %(message)s")


def field(d, path, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def ioc_type_ids(base, headers):
    """Resolve IOC type ids by name once per call; IRIS ships 'domain' and 'ip-src'."""
    r = requests.get(f"{base}/manage/ioc-types/list", headers=headers, verify=VERIFY_TLS, timeout=TIMEOUT)
    r.raise_for_status()
    return {t["type_name"]: t["type_id"] for t in r.json().get("data", [])}


def alert_status_id(base, headers):
    """IRIS requires a status; use "New", fall back to its usual id."""
    try:
        r = requests.get(f"{base}/manage/alert-status/list", headers=headers, verify=VERIFY_TLS, timeout=TIMEOUT)
        for s in r.json().get("data", []):
            if s.get("status_name", "").lower() == "new":
                return s["status_id"]
    except Exception:  # noqa: BLE001
        pass
    return 2


def build_alert(alert, types, status_id):
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))
    data = alert.get("data", {})
    pa = data.get("pihole_analytics", {})

    domain = pa.get("registrable") or pa.get("domain") or field(data, "dns.domain")
    client = pa.get("client") or data.get("srcip") or field(data, "dns.client")
    agent = field(alert, "agent.name", "manager")

    iocs = []
    if domain and "domain" in types:
        iocs.append({"ioc_value": domain, "ioc_type_id": types["domain"], "ioc_tlp_id": 2,
                     "ioc_description": f"from Wazuh rule {rule.get('id')}", "ioc_tags": "dns"})
    if client and "ip-src" in types:
        iocs.append({"ioc_value": client, "ioc_type_id": types["ip-src"], "ioc_tlp_id": 2,
                     "ioc_description": "internal client", "ioc_tags": "client"})

    ts = alert.get("timestamp", "")
    try:
        event_time = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        event_time = event_time.strftime("%Y-%m-%dT%H:%M:%S.000")
    except ValueError:
        event_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    context = {
        "wazuh_rule_id": rule.get("id"),
        "wazuh_level": level,
        "wazuh_groups": rule.get("groups", []),
        "mitre": field(rule, "mitre.id", []),
        "agent": agent,
        "client": client,
        "domain": domain,
    }
    if pa:
        context["pihole_analytics"] = pa

    return {
        "alert_title": f"[Wazuh {rule.get('id')}] {rule.get('description', 'alert')[:180]}",
        "alert_description": rule.get("description", ""),
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id", ""),
        "alert_source_link": "https://192.168.178.220/app/wazuh",
        "alert_source_event_time": event_time,
        "alert_severity_id": severity(level),
        "alert_status_id": status_id,
        "alert_customer_id": CUSTOMER_ID,
        "alert_tags": ",".join(["wazuh", "dns"] + [g for g in rule.get("groups", []) if g.startswith("dns_")]),
        "alert_iocs": iocs,
        "alert_context": context,
        "alert_source_content": alert,
    }


def main():
    if len(sys.argv) < 4:
        logging.error("usage: custom-iris <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, api_key, base = sys.argv[1], sys.argv[2], sys.argv[3].rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    with open(alert_file, encoding="utf-8") as fh:
        alert = json.loads(fh.read().strip().splitlines()[-1])

    try:
        types = ioc_type_ids(base, headers)
        payload = build_alert(alert, types, alert_status_id(base, headers))
        r = requests.post(f"{base}/alerts/add", headers=headers, json=payload,
                          verify=VERIFY_TLS, timeout=TIMEOUT)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code == 200 and body.get("status") == "success":
            logging.info("rule %s -> IRIS alert %s", field(alert, "rule.id"), field(body, "data.alert_id"))
            return 0
        logging.error("rule %s -> HTTP %s: %s", field(alert, "rule.id"), r.status_code, r.text[:300])
        return 1
    except Exception as exc:  # noqa: BLE001 - one integration call must never take the manager down
        logging.error("rule %s -> %s", field(alert, "rule.id"), exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
