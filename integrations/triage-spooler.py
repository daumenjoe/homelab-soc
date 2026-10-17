#!/var/ossec/framework/python/bin/python3
"""triage-spooler: delivers the LLM triage for IRIS alerts that were created while the LLM host was off.

custom-iris creates the IRIS alert at once (tag llm-pending) and keeps alert + enrichment as one
JSON file per case in SPOOL_DIR (see custom-iris.spool). This script runs from a systemd timer
every 120 s and does nothing unless (a) the spool is not empty and (b) the Ollama API answers.
Then it processes the files in order with the functions imported from custom-iris (decision model,
triage, second opinion), posts the result as a comment on the IRIS alert, swaps llm-pending for the
dm-/llm- tags and updates the alert context. The host is never woken up and no case expires:
a verdict that is three days late is still a verdict (Befund 43).

Install: /var/ossec/integrations/triage-spooler (root:wazuh 0750), run as wazuh (same as the integration)
Units:   triage-spooler.service + triage-spooler.timer (OnUnitActiveSec=120)
Log:     /var/ossec/logs/integrations.log, prefix triage-spooler
Manual:  triage-spooler --list              queue with age and attempts, no delivery
         triage-spooler --replay <file>     run custom-iris on one alert file (key/url from ossec.conf)
"""
import fcntl
import importlib.machinery
import json
import logging
import re
import subprocess
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path

import requests

INTEGRATION = "/var/ossec/integrations/custom-iris"
OSSEC_CONF = "/var/ossec/etc/ossec.conf"
LOG = "/var/ossec/logs/integrations.log"
MAX_ATTEMPTS = 3   # LLM errors (timeout, bad JSON) per case before the error itself is delivered

logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s triage-spooler: %(message)s")


def load_integration():
    """Import custom-iris (no .py suffix) as a module: same config, same prompt, same functions."""
    loader = importlib.machinery.SourceFileLoader("custom_iris", INTEGRATION)
    mod = types.ModuleType(loader.name)
    loader.exec_module(mod)
    return mod


def iris_target():
    """api_key and hook_url from the custom-iris block in ossec.conf: one copy of the key, not two."""
    text = Path(OSSEC_CONF).read_text(encoding="utf-8")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    for block in re.findall(r"<integration>(.*?)</integration>", text, flags=re.S):
        if re.search(r"<name>\s*custom-iris\s*</name>", block):
            key = re.search(r"<api_key>\s*(.*?)\s*</api_key>", block, flags=re.S)
            url = re.search(r"<hook_url>\s*(.*?)\s*</hook_url>", block, flags=re.S)
            if key and url:
                return key.group(1), url.group(1).rstrip("/")
    raise RuntimeError("no <integration> custom-iris with api_key and hook_url in ossec.conf")


def age(iso):
    secs = int((datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds())
    d, h, m = secs // 86400, secs % 86400 // 3600, secs % 3600 // 60
    return (f"{d}d" if d else "") + f"{h}h{m:02d}m"


def deliver(ci, item, cfg, base, headers, verify):
    """Run the triage for one spooled case and write it to IRIS.
    Returns 'done', 'gone' (alert no longer in IRIS), 'retry' (LLM error, attempts left) or 'unreachable'."""
    alert, enrichment, alert_id = item["alert"], item["enrichment"], item["alert_id"]
    r = requests.get(f"{base}/alerts/{alert_id}", headers=headers, verify=verify, timeout=ci.TIMEOUT)
    if r.status_code == 404:
        return "gone"   # merged or deleted meanwhile: no LLM time for it
    r.raise_for_status()
    data = r.json().get("data", {})

    t0 = time.time()
    tags = ci.run_triage(alert, enrichment, cfg)
    triage = enrichment["llm_triage"]
    if ci.llm_unreachable(triage):
        return "unreachable"
    if str(triage.get("llm", "")).startswith("error") and item["attempts"] < MAX_ATTEMPTS:
        return "retry"
    text = ci.triage_text(enrichment).strip() or f"LLM triage failed after {item['attempts']} attempts: {triage.get('llm')}"
    comment = (f"Deferred triage: the LLM host was off when this alert was created "
               f"({item['spooled']}), delivered {age(item['spooled'])} later.\n\n{text}")
    r = requests.post(f"{base}/alerts/{alert_id}/comments/add", headers=headers, verify=verify, timeout=ci.TIMEOUT,
                      json={"comment_text": comment})
    r.raise_for_status()
    old = [t for t in (data.get("alert_tags") or "").split(",") if t and t != "llm-pending"]
    context = data.get("alert_context") or {}
    if isinstance(context, dict):
        context["enrichment"] = enrichment
    r = requests.post(f"{base}/alerts/update/{alert_id}", headers=headers, verify=verify, timeout=ci.TIMEOUT,
                      json={"alert_tags": ",".join(dict.fromkeys(old + tags)), "alert_context": context})
    r.raise_for_status()
    logging.info("alert %s rule %s -> %s (spooled %s ago, %.1fs)", alert_id, item.get("rule_id"),
                 ", ".join(tags) or "no verdict", age(item["spooled"]), time.time() - t0)
    return "done"


def main():
    ci = load_integration()
    cfg = ci.load_config()
    spool = Path(ci.SPOOL_DIR)
    files = sorted(spool.glob("*.json")) if spool.is_dir() else []

    if "--list" in sys.argv:
        for f in files:
            item = json.loads(f.read_text(encoding="utf-8"))
            print(f"{age(item['spooled']):>9}  alert {item['alert_id']:<6} rule {item.get('rule_id')}  attempts {item['attempts']}  {f.name}")
        print(f"{len(files)} queued")
        return 0

    if len(sys.argv) == 3 and sys.argv[1] == "--replay":   # feed one alert file through the integration, key from ossec.conf
        api_key, base = iris_target()
        return subprocess.run([INTEGRATION, sys.argv[2], api_key, base], check=False).returncode

    if not files or not cfg["llm_url"]:
        return 0
    spool.mkdir(parents=True, exist_ok=True)
    lock = open(spool / ".lock", "w", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0   # the previous run is still delivering
    try:   # same probe as the integration; silent while the host is off, that is the normal state
        requests.get(f"{cfg['llm_url'].rstrip('/')}/api/tags", timeout=3).raise_for_status()
    except Exception:  # noqa: BLE001
        return 0

    api_key, base = iris_target()
    verify = bool(cfg["verify_tls"])
    if not verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    logging.info("LLM host is up, %d case(s) queued", len(files))

    done = 0
    for f in files:
        item = json.loads(f.read_text(encoding="utf-8"))
        item["attempts"] += 1
        f.write_text(json.dumps(item, ensure_ascii=False), encoding="utf-8")   # counted before the run: a crash counts too
        try:
            result = deliver(ci, item, cfg, base, headers, verify)
        except Exception as exc:  # noqa: BLE001   IRIS trouble: keep the file, try again next tick
            logging.error("alert %s -> %s, stopping this run", item["alert_id"], exc)
            break
        if result == "unreachable":
            logging.info("LLM host went away after %d of %d, the rest waits", done, len(files))
            break
        if result == "retry":
            logging.warning("alert %s -> %s (attempt %d of %d)", item["alert_id"], item["enrichment"]["llm_triage"].get("llm"),
                            item["attempts"], MAX_ATTEMPTS)
            continue
        if result == "gone":
            logging.info("alert %s no longer in IRIS, dropped", item["alert_id"])
        f.unlink()
        done += 1
    if done:
        logging.info("%d of %d delivered", done, len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
