# Triage-Evalset

Sieben angereicherte Alerts mit erwartetem Verdict (`cases/*.json`), die typische Triage-Situationen
abdecken: Verhaltensbefund mit veralteter Threat-Intel, eindeutig bösartig, Hersteller-Telemetrie,
NRD+DGA ohne Bestätigung, Honeypot-Brute-Force ohne TI, fremder Container, TI-Fehltreffer auf einer
Großdomain. Alle Domains sind erfunden (`.example`).

`run-triage-eval.py` nutzt die Prompt-Logik aus `integrations/custom-iris.py` (kein Kopieren, kein
Auseinanderlaufen) und schickt jeden Fall durch die angegebenen Modelle, optional mehrfach, um die
Streuung zu sehen. Ausgabe als Tabelle plus `results-*.jsonl`.

    ./run-triage-eval.py --url http://llm.example:11434 gemma4:12b qwen3:14b --runs 2

Ein Modell, das hier 7/7 trifft, ist noch kein Beweis; eines, das bei Fall 01 „benign" mit hoher
Konfidenz sagt, hat den Kern eines Alerts übersehen – und genau das soll dieser Test sichtbar machen.
