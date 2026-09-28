#!/usr/bin/env python3
"""Triage-Evalset: schickt jeden Fall aus cases/ durch die angegebenen Modelle und vergleicht
das Verdict mit der Erwartung. Nutzt exakt die Prompt-Logik von integrations/custom-iris.py.

  ./run-triage-eval.py --url http://llm:11434 gemma4:12b qwen3:14b --runs 2
  ./run-triage-eval.py --url http://llm:11434 --list

Ausgabe: Tabelle je Fall/Modell/Lauf (verdict, confidence, seconds, ok) und Trefferquote je Modell.
Schreibt results-<datum>.jsonl fuer spaetere Auswertung.
"""
import argparse, importlib.util, json, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = sorted((HERE / "cases").glob("*.json"))
CI = HERE.parent.parent / "integrations" / "custom-iris.py"
if not CI.exists():
    CI = HERE.parent / "integrations" / "custom-iris.py"

def load_ci():
    src = CI.read_text(encoding="utf-8").replace('LOG = "/var/ossec/logs/integrations.log"', 'LOG = "/tmp/triage-eval.log"')
    ns = {"__name__": "ci"}
    exec(compile(src, str(CI), "exec"), ns)
    return ns

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("models", nargs="*")
    ap.add_argument("--url", required=True)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for c in CASES:
            d = json.loads(c.read_text(encoding="utf-8")); print(f"{c.stem:32} expect {'/'.join(d['expect']):22} {d['note']}")
        return
    if not a.models:
        sys.exit("Modelle angeben, z. B. gemma4:12b qwen3:14b")
    ci = load_ci()
    out = HERE / f"results-{time.strftime('%Y%m%d-%H%M')}.jsonl"
    score = {m: [0, 0] for m in a.models}
    print(f"{'case':32} {'model':18} run  verdict     conf   sec  ok")
    with open(out, "w", encoding="utf-8") as fh:
        for c in CASES:
            d = json.loads(c.read_text(encoding="utf-8"))
            for m in a.models:
                cfg = dict(ci["DEFAULTS"], llm_url=a.url, llm_model=m, llm_timeout=a.timeout, llm_num_ctx=a.num_ctx)
                for r in range(1, a.runs + 1):
                    t = ci["enrich_llm"](d["alert"], d["enrichment"], cfg)
                    ok = t.get("verdict") in d["expect"]
                    score[m][0] += ok; score[m][1] += 1
                    print(f"{c.stem:32} {m:18} {r:>3}  {str(t.get('verdict', t.get('llm')))[:10]:10} {str(t.get('confidence', '-')):>5} {str(t.get('seconds', '-')):>5}  {'OK' if ok else '--'}")
                    fh.write(json.dumps({"case": c.stem, "model": m, "run": r, "expect": d["expect"], "triage": t}, ensure_ascii=False) + "\n")
    print()
    verdicts = {}
    for line in open(out, encoding="utf-8"):
        rec = json.loads(line); verdicts.setdefault((rec["model"], rec["case"]), []).append(rec["triage"].get("verdict"))
    for m, (hit, n) in score.items():
        pairs = [v for (mm, _), v in verdicts.items() if mm == m and len(v) > 1]
        stable = sum(1 for v in pairs if len(set(v)) == 1)
        cons = f", stabil {stable}/{len(pairs)} Faelle" if pairs else ""
        print(f"{m:18} {hit}/{n} Treffer{cons}")
    print("Ergebnisse:", out)

if __name__ == "__main__":
    main()
