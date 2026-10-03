#!/usr/bin/env python3
"""Decision-model eval: run the seven triage cases through Ollama's /v1/systemone (nimble, tev1 ...)
and compare the chosen verdict with the expectation. Prints the full probability distribution,
so calibration is visible, not just hit/miss.

  ./run-decision-eval.py --url http://llm:11434 nimble tev1 --runs 2
"""
import argparse, json, sys, time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
CASES = sorted((HERE / "cases").glob("*.json"))

QUESTIONS = {
    "verdict": {
        "type": "choice",
        "instructions": ("You are doing first-level SOC triage of this alert. Behaviour indicators (tunneling metrics, "
                         "brute force, unexpected containers) matter even when the destination reputation is clean; "
                         "stale threat intel on old domains and vendor telemetry are common false positives. "
                         "Which verdict fits?"),
        "criteria": {
            "benign": "nothing to do, the alert can be closed",
            "suspicious": "a human must investigate before any action",
            "malicious": "strong evidence of an attack or compromise, act now",
        },
    },
    "needs_human": {"type": "noul", "instructions": "Does a human analyst need to look at this alert?"},
}


def state_text(case):
    a = case["alert"]
    return json.dumps({"rule": a["rule"], "agent": a["agent"], "event": a["data"], "enrichment": case["enrichment"]},
                      ensure_ascii=False, default=str)


def ask(url, model, state):
    t0 = time.time()
    r = requests.post(f"{url.rstrip('/')}/v1/systemone", json={"model": model, "state": state, "questions": QUESTIONS}, timeout=300)
    r.raise_for_status()
    return r.json()["answers"], round(time.time() - t0, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("models", nargs="+")
    ap.add_argument("--url", required=True)
    ap.add_argument("--runs", type=int, default=1)
    a = ap.parse_args()
    out = HERE / f"results-decision-{time.strftime('%Y%m%d-%H%M')}.jsonl"
    score = {m: [0, 0] for m in a.models}
    print(f"{'case':32} {'model':10} run  verdict     p(ben/sus/mal)      human   sec  ok")
    with open(out, "w", encoding="utf-8") as fh:
        for c in CASES:
            d = json.loads(c.read_text(encoding="utf-8"))
            for m in a.models:
                for r in range(1, a.runs + 1):
                    try:
                        ans, sec = ask(a.url, m, state_text(d))
                        v = ans["verdict"]; p = v["probabilities"]; h = ans["needs_human"].get("noul")
                        ok = v["choice"] in d["expect"]
                        dist = f"{p.get('benign',0):.2f}/{p.get('suspicious',0):.2f}/{p.get('malicious',0):.2f}"
                        print(f"{c.stem:32} {m:10} {r:>3}  {v['choice']:10} {dist:18} {h:5.2f} {sec:5}  {'OK' if ok else '--'}")
                        rec = {"case": c.stem, "model": m, "run": r, "expect": d["expect"], "answers": ans, "seconds": sec}
                    except Exception as exc:  # noqa: BLE001
                        ok = False
                        print(f"{c.stem:32} {m:10} {r:>3}  error: {type(exc).__name__}")
                        rec = {"case": c.stem, "model": m, "run": r, "error": type(exc).__name__}
                    score[m][0] += ok; score[m][1] += 1
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print()
    for m, (hit, n) in score.items():
        print(f"{m:10} {hit}/{n} Treffer")
    print("Ergebnisse:", out)


if __name__ == "__main__":
    main()
