#!/usr/bin/env python3
"""Erzeugt docs/RULES.md aus rules/*.xml.

Bewusst regex-basiert: Wazuh-Regeldateien haben mehrere Root-Elemente und
PCRE2-Ausdrücke, an denen strikte XML-Parser scheitern.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RULE = re.compile(r"<rule\s+([^>]*)>(.*?)</rule>", re.S)
ATTR = re.compile(r'(\w+)="([^"]*)"')


def tag(body, name):
    return [m.strip() for m in re.findall(rf"<{name}[^>]*>(.*?)</{name}>", body, re.S)]


def main():
    files = sorted(f for f in (REPO / "rules").glob("*.xml") if "local" not in f.name)
    if not files:
        sys.exit("keine Dateien in rules/ – erst scripts/collect.sh ausführen")
    out = ["# Regelübersicht", "",
           "Erzeugt mit `scripts/gen-rule-table.py` – nicht von Hand pflegen.", ""]
    total = 0
    for f in files:
        text = re.sub(r"<!--.*?-->", "", f.read_text(encoding="utf-8"), flags=re.S)
        out += [f"## `{f.name}`", "",
                "| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |",
                "|---|---|---|---|---|---|"]
        for attrs, body in RULE.findall(text):
            a = dict(ATTR.findall(attrs))
            parent = ", ".join(tag(body, "if_sid") + [f"{x} (freq)" for x in tag(body, "if_matched_sid")])
            freq = f'{a["frequency"]}× / {a.get("timeframe", "?")} s' if "frequency" in a else ""
            mitre = ", ".join(i for m in tag(body, "mitre") for i in tag(m, "id"))
            desc = " ".join(tag(body, "description")).replace("|", "\\|")
            out.append(f'| {a.get("id", "?")} | {a.get("level", "?")} | {parent} | {freq} | {mitre} | {desc} |')
            total += 1
        out.append("")
    dest = REPO / "docs" / "RULES.md"
    dest.write_text("\n".join(out), encoding="utf-8")
    print(f"{total} Regeln aus {len(files)} Datei(en) -> {dest}")


if __name__ == "__main__":
    main()
