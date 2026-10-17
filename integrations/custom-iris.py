#!/var/ossec/framework/python/bin/python3
"""Wazuh custom integration: forward alerts to DFIR-IRIS as IRIS alerts, enriched.

Called by wazuh-integratord as:  custom-iris <alert_file> <api_key> <hook_url>

Enrichment (best-effort, short timeouts; a failure never blocks the alert):
  - RDAP:        registration date -> domain age in days      (no key needed)
  - VirusTotal:  last_analysis_stats, categories, reputation  (free API key)
  - Reverse DNS: PTR of the internal client -> device name    (via Pi-hole / router)
  - MISP:        stored events and feed cache for domain / registrable domain
  - Decision:    local Ollama decision model (/v1/systemone) returns a calibrated verdict
                 distribution and a needs_human probability in ~2 s; gates the LLM triage
  - LLM triage:  local Ollama model reads the enriched alert, returns verdict + reasoning
                 (advisory only: never changes severity, never acts)
  - Spool:       if the LLM host is switched off, the IRIS alert is created at once with the
                 tag llm-pending and alert + enrichment are kept in SPOOL_DIR; triage-spooler
                 (systemd timer, 120 s) delivers the verdict as an IRIS comment once the host is up

Optional config /var/ossec/etc/custom-iris.json (root:wazuh 640):
  {"customer_id": 2, "vt_api_key": "...", "dashboard_url": "https://wazuh.example",
   "verify_tls": true, "nrd_days": 30, "vt_per_minute": 4, "vt_per_day": 500,
   "misp_url": "https://misp.example", "misp_api_key": "...", "misp_verify_tls": true,
   "llm_url": "http://llm.example:11434", "llm_model": "qwen2.5:7b", "llm_timeout": 90, "llm_num_ctx": 8192}

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

VERSION = "3.0"
CONFIG_PATH = "/var/ossec/etc/custom-iris.json"
DEFAULTS = {"customer_id": 2, "vt_api_key": "", "dashboard_url": "https://wazuh.provinglab.de/app/wazuh",
            "verify_tls": True, "nrd_days": 30, "vt_per_minute": 4, "vt_per_day": 500,
            "misp_url": "", "misp_api_key": "", "misp_verify_tls": True, "misp_stale_days": 365,
            "llm_url": "", "llm_model": "qwen2.5:7b", "llm_timeout": 90, "llm_num_ctx": 8192,
            "dm_model": "", "dm_gate": 0.5,
            "infra_hosts": {}}   # {"192.168.0.1": "gateway/router", ...}: Betrieb, nie isolieren (Befund 42)
VT_STATE = "/var/ossec/var/custom-iris-vt.json"   # local request counter, shared by parallel runs
SPOOL_DIR = "/var/ossec/var/triage-spool"          # alerts waiting for the LLM host (Befund 43)
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


def enrich_misp(values, cfg):
    """Look the indicators up in stored MISP events and in the feed cache."""
    if not cfg["misp_url"] or not cfg["misp_api_key"]:
        return {"misp": "not configured"}
    base = cfg["misp_url"].rstrip("/")
    headers = {"Authorization": cfg["misp_api_key"], "Accept": "application/json", "Content-Type": "application/json"}
    verify = bool(cfg["misp_verify_tls"])
    values = [v for v in dict.fromkeys(values) if v]
    out = {"queried": values, "event_hits": 0, "events": [], "feed_hits": 0, "feeds": []}
    try:
        r = requests.post(f"{base}/attributes/restSearch", headers=headers, verify=verify, timeout=ENRICH_TIMEOUT,
                          json={"returnFormat": "json", "value": values, "limit": 25, "includeEventTags": True, "includeDecayScore": True})
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        out["event_hits"] = len(attrs)
        seen = {}
        for a in attrs:
            ev = a.get("Event", {})
            scores = [d.get("score") for d in a.get("decay_score", []) if isinstance(d, dict)]
            try:
                ev_age = (datetime.now(timezone.utc).date() - datetime.fromisoformat(ev.get("date", "")).date()).days
            except Exception:  # noqa: BLE001
                ev_age = None
            seen.setdefault(ev.get("id"), {"event_id": ev.get("id"), "info": ev.get("info", "")[:100],
                                            "event_date": ev.get("date"), "event_age_days": ev_age,
                                            "decay_score": max(scores) if scores else None,
                                            "decayed": all(d.get("decayed") for d in a.get("decay_score", []) if isinstance(d, dict)) if scores else None,
                                            "type": a.get("type"), "to_ids": a.get("to_ids"),
                                            "link": f"{base}/events/view/{ev.get('id')}"})
        out["events"] = list(seen.values())[:5]
        def stale(e):   # MISP decay score wins; otherwise the event date decides
            if e.get("decayed") is not None:
                return e["decayed"]
            return e.get("event_age_days") is not None and e["event_age_days"] > int(cfg["misp_stale_days"])
        for e in out["events"]:
            e["stale"] = stale(e)
        out["all_decayed"] = bool(out["events"]) and all(e["stale"] for e in out["events"])
    except Exception as exc:  # noqa: BLE001
        out["events_error"] = f"{type(exc).__name__}"
    try:
        r = requests.post(f"{base}/feeds/searchCaches", headers=headers, verify=verify, timeout=ENRICH_TIMEOUT,
                          json={"value": values})
        r.raise_for_status()
        hits = r.json() if isinstance(r.json(), list) else []
        feeds = sorted({f.get("Feed", {}).get("name", "?") for h in hits for f in h.get("Feed", []) if isinstance(f, dict)}
                       | {h.get("Feed", {}).get("name") for h in hits if isinstance(h.get("Feed"), dict)} - {None})
        out["feed_hits"] = len(hits)
        out["feeds"] = feeds[:8]
    except Exception as exc:  # noqa: BLE001
        out["feeds_error"] = f"{type(exc).__name__}"
    return out


LLM_SYSTEM = (
    "You are a senior SOC analyst doing first-level triage of a single SIEM alert from a small network. "
    "You get the alert plus enrichment (domain age, VirusTotal, MISP threat intel, device name). "
    "Judge whether this needs a human investigation. Be concrete, cite the enrichment facts that drive your verdict, "
    "and remember that old threat-intel hits on re-registered domains and vendor telemetry are common false positives. "
    "Verdict scale: malicious = strong evidence of an attack or compromise, act now (isolate, forensics); "
    "suspicious = needs a human investigation before any action; benign = can be closed, explain why; "
    "unknown = only if the data is truly insufficient. If your own next step is to isolate or contain a host, the verdict is malicious. "
    "If the facts contain an 'infrastructure' map, those hosts are this network's own gateway, DNS, SIEM and servers: "
    "scans, port changes and setting changes originating from them are normal operation unless the enrichment shows compromise, "
    "and isolating them is never the next step; recommend checking the service instead. "
    "A missing process name (null) in Velociraptor port events is a sensor limitation on some hosts, not evidence of hiding. "
    "Confidence is an integer from 1 to 100, never 0. Answer in English, in the requested JSON only."
)
LLM_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious", "unknown"]},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "summary": {"type": "string"},
        "reasoning": {"type": "string"},
        "next_step": {"type": "string"},
    },
    "required": ["verdict", "confidence", "summary", "reasoning", "next_step"],
}


DM_QUESTIONS = {
    "verdict": {
        "type": "choice",
        "instructions": ("You are doing first-level SOC triage of this alert. Behaviour indicators (tunneling metrics, "
                         "brute force, unexpected containers) matter even when the destination reputation is clean; "
                         "stale threat intel on old domains and vendor telemetry are common false positives. "
                         "Which verdict fits?"),
        "criteria": {"benign": "nothing to do, the alert can be closed",
                     "suspicious": "a human must investigate before any action",
                     "malicious": "strong evidence of an attack or compromise, act now"},
    },
    "needs_human": {"type": "noul", "instructions": "Does a human analyst need to look at this alert?"},
}


def enrich_decision(alert, enrichment, cfg):
    """Calibrated verdict distribution from a decision model. Cheap (~2 s), deterministic, advisory."""
    if not cfg["llm_url"] or not cfg.get("dm_model"):
        return {"decision": "not configured"}
    rule, data = alert.get("rule", {}), alert.get("data", {})
    state = json.dumps({"rule": {"id": rule.get("id"), "level": rule.get("level"), "description": rule.get("description"),
                                "mitre": field(rule, "mitre.id", []), "groups": rule.get("groups", [])},
                        "agent": field(alert, "agent.name"),
                        "event": data.get("pihole_analytics") or data.get("dns") or {k: v for k, v in data.items() if k != "integration"},
                        "enrichment": enrichment}, ensure_ascii=False, default=str)[:60000]
    t0 = time.time()
    try:
        requests.get(f"{cfg['llm_url'].rstrip('/')}/api/tags", timeout=3).raise_for_status()
        r = requests.post(f"{cfg['llm_url'].rstrip('/')}/v1/systemone", timeout=120,
                          json={"model": cfg["dm_model"], "state": state, "questions": DM_QUESTIONS})
        r.raise_for_status()
        ans = r.json()["answers"]
        v = ans["verdict"]
        return {"model": cfg["dm_model"], "verdict": v["choice"], "probabilities": {k: round(x, 3) for k, x in v["probabilities"].items()},
                "confidence": round(v.get("confidence", 0), 3), "needs_human": round(ans["needs_human"].get("noul", 0), 3),
                "seconds": round(time.time() - t0, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"decision": f"error: {type(exc).__name__}", "model": cfg["dm_model"], "seconds": round(time.time() - t0, 1)}


def enrich_llm(alert, enrichment, cfg):
    """Ask the local model for a triage opinion. Advisory only."""
    if not cfg["llm_url"]:
        return {"llm": "not configured"}
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    facts = {
        "rule": {"id": rule.get("id"), "level": rule.get("level"), "description": rule.get("description"),
                 "mitre": field(rule, "mitre.id", []), "groups": rule.get("groups", [])},
        "agent": field(alert, "agent.name"),
        "event": data.get("pihole_analytics") or data.get("dns") or {k: v for k, v in data.items() if k not in ("integration",)},
        "enrichment": enrichment,
    }
    if cfg.get("infra_hosts"):
        facts["infrastructure"] = cfg["infra_hosts"]
    body = {
        "model": cfg["llm_model"], "stream": False, "think": False, "format": LLM_SCHEMA,
        "options": {"temperature": 0.2, "num_ctx": int(cfg["llm_num_ctx"])},
        "messages": [{"role": "system", "content": LLM_SYSTEM},
                     {"role": "user", "content": "Alert and enrichment as JSON:\n" + json.dumps(facts, ensure_ascii=False, default=str)[:20000]}],
    }
    t0 = time.time()
    try:   # quick reachability probe: the LLM host may simply be switched off
        requests.get(f"{cfg['llm_url'].rstrip('/')}/api/tags", timeout=3).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        return {"llm": f"unreachable: {type(exc).__name__}", "model": cfg["llm_model"], "seconds": round(time.time() - t0, 1)}
    try:
        r = requests.post(f"{cfg['llm_url'].rstrip('/')}/api/chat", json=body, timeout=int(cfg["llm_timeout"]))
        r.raise_for_status()
        out = json.loads(r.json()["message"]["content"])
        out["model"] = cfg["llm_model"]
        out["seconds"] = round(time.time() - t0, 1)
        return out
    except Exception as exc:  # noqa: BLE001
        return {"llm": f"error: {type(exc).__name__}", "model": cfg["llm_model"], "seconds": round(time.time() - t0, 1)}


def enrich_client(ip):
    try:
        socket.setdefaulttimeout(3)
        return {"hostname": socket.gethostbyaddr(ip)[0]}
    except Exception:  # noqa: BLE001
        return {"hostname": ""}


def llm_unreachable(opinion):
    return "unreachable" in str(opinion.get("llm", ""))


def run_triage(alert, enrichment, cfg):
    """Decision model, LLM triage and second opinion. Adds decision / llm_triage /
    llm_second_opinion to enrichment and returns the tags. Shared with triage-spooler."""
    tags = []
    decision = enrich_decision(alert, enrichment, cfg)
    enrichment["decision"] = decision
    if decision.get("verdict"):
        tags.append(f"dm-{decision['verdict']}")
    # LLM triage only when the decision model wants a human (or is unavailable): dm_gate = needs_human threshold, 0 = always
    run_llm = not decision.get("verdict") or decision["needs_human"] >= float(cfg.get("dm_gate", 0.5)) or decision["verdict"] != "benign"
    models = (cfg["llm_model"] if isinstance(cfg["llm_model"], list) else [cfg["llm_model"]]) if run_llm else []
    opinions = []
    for m in models:
        opinions.append(enrich_llm(alert, enrichment, dict(cfg, llm_model=m)))
        if llm_unreachable(opinions[-1]):
            break   # host is off: do not wait for the second opinion either
    triage = opinions[0] if opinions else {"llm": "skipped: decision model says benign, no human needed"}
    enrichment["llm_triage"] = triage
    if len(opinions) > 1:
        enrichment["llm_second_opinion"] = opinions[1]
    if triage.get("verdict"):
        tags.append(f"llm-{triage['verdict']}")
        second = opinions[1] if len(opinions) > 1 else {}
        if second.get("verdict") and second["verdict"] != triage["verdict"]:
            tags.append("llm-disagree")
    elif llm_unreachable(triage):
        tags.append("llm-pending")   # host is off: main() spools the case, triage-spooler delivers later
    return tags


def triage_text(enrichment):
    """Decision, triage and second opinion as text: appended to the IRIS description,
    or posted as a comment by triage-spooler. Empty when nothing has a verdict."""
    decision = enrichment.get("decision", {})
    triage = enrichment.get("llm_triage", {})
    second = enrichment.get("llm_second_opinion", {})
    text = ""
    if decision.get("verdict"):
        pr = decision["probabilities"]
        text += (f"\n\nDecision ({decision['model']}, {decision['seconds']}s): {decision['verdict'].upper()} "
                 f"{round(pr.get(decision['verdict'], 0) * 100)}% [benign {round(pr.get('benign', 0) * 100)} / suspicious "
                 f"{round(pr.get('suspicious', 0) * 100)} / malicious {round(pr.get('malicious', 0) * 100)}], needs human "
                 f"{round(decision['needs_human'] * 100)}%")
    if triage.get("verdict"):
        text += (f"\n\nLLM triage ({triage['model']}, {triage['seconds']}s): {triage['verdict'].upper()} "
                 f"({triage['confidence']}%) - {triage['summary']}\nReasoning: {triage['reasoning']}\nNext step: {triage['next_step']}")
        if second.get("verdict"):
            agree = "agrees" if second["verdict"] == triage["verdict"] else "DISAGREES"
            text += (f"\n\nSecond opinion ({second['model']}, {second['seconds']}s) {agree}: {second['verdict'].upper()} "
                     f"({second['confidence']}%) - {second['summary']}")
    return text


def spool(alert, enrichment, alert_id):
    """LLM host is off: keep alert + enrichment (without the failed verdicts) so that
    triage-spooler can run the triage later and comment on the IRIS alert."""
    try:
        keep = {k: v for k, v in enrichment.items() if k not in ("decision", "llm_triage", "llm_second_opinion")}
        now = datetime.now(timezone.utc)
        name = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{alert_id}.json"
        Path(SPOOL_DIR).mkdir(parents=True, exist_ok=True)
        tmp = Path(SPOOL_DIR) / (name + ".tmp")
        tmp.write_text(json.dumps({"alert_id": alert_id, "rule_id": field(alert, "rule.id"),
                                   "spooled": now.isoformat(timespec="seconds"), "attempts": 0,
                                   "alert": alert, "enrichment": keep}, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.rename(Path(SPOOL_DIR) / name)   # atomic: the spooler only picks up *.json
        logging.info("alert %s spooled for later triage (%s)", alert_id, name)
    except Exception as exc:  # noqa: BLE001
        logging.error("alert %s could not be spooled: %s", alert_id, exc)


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

    domain = pa.get("registrable") or pa.get("domain") or field(data, "dns.domain") or field(data, "tls.sni")
    regdom = pa.get("registrable") or domain
    client = pa.get("client") or data.get("srcip") or field(data, "dns.client") or data.get("src_host") or data.get("src_ip")
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
        enrichment["misp"] = enrich_misp([domain, regdom], cfg)
        mp_ = enrichment["misp"]
        if mp_.get("feed_hits") or (mp_.get("event_hits") and not mp_.get("all_decayed")):
            tags.append("misp-hit")
            if sev < 6:
                sev += 1
        elif mp_.get("event_hits"):
            tags.append("misp-stale")   # only decayed indicators: context, not escalation
    hostname = ""
    if client:
        hostname = enrich_client(client)["hostname"]
        enrichment["client"] = {"ip": client, "hostname": hostname or "no PTR"}

    tags += run_triage(alert, enrichment, cfg)

    summary = []
    rd, vt = enrichment.get("rdap", {}), enrichment.get("virustotal", {})
    if "age_days" in rd:
        summary.append(f"domain age {rd['age_days']} d" + (" (NRD)" if rd.get("newly_registered") else ""))
    if "malicious" in vt:
        summary.append(f"VirusTotal {vt['malicious']}/{vt['engines']} malicious")
    mp = enrichment.get("misp", {})
    if "event_hits" in mp:
        summary.append(f"MISP {mp['event_hits']} event / {mp['feed_hits']} feed hits" + (" (all decayed)" if mp.get("all_decayed") else "") + (f" ({', '.join(mp['feeds'][:3])})" if mp.get("feeds") else ""))
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
    description += triage_text(enrichment)

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
        "alert_tags": ",".join(["wazuh", "dns"] + [g for g in rule.get("groups", []) if g.startswith("dns_")] + tags),
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
            alert_id = field(body, "data.alert_id")
            logging.info("rule %s -> IRIS alert %s (%s)", field(alert, "rule.id"), alert_id, extra)
            if "llm-pending" in payload["alert_tags"].split(","):
                spool(alert, payload["alert_context"]["enrichment"], alert_id)
            return 0
        logging.error("rule %s -> HTTP %s: %s", field(alert, "rule.id"), r.status_code, r.text[:300])
        return 1
    except Exception as exc:  # noqa: BLE001
        logging.error("rule %s -> %s", field(alert, "rule.id"), exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
