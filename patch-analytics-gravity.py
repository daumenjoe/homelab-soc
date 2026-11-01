#!/usr/bin/env python3
"""Patch fuer analytics/pihole_analytics.py (Befund 46):
   Beaconing-Events bekommen das Feld "tracker": true, wenn die Domain (oder eine
   Elterndomain) in Pi-holes gravity.db steht (Blocklisten oder exakte Denylist).
   Fuer Clients, die am Blocking vorbei duerfen, ist ein regelmaessiger Takt zu
   so einer Domain ein Werbeplatz, kein C2; Wazuh stuft das per Kindregel ab.
   Aufruf: python3 patch-analytics-gravity.py analytics/pihole_analytics.py
   Ersetzt exakt einmal je Stelle, sonst Abbruch ohne Schreiben."""
import sys

p = sys.argv[1]
s = open(p, encoding="utf-8").read()
orig = s

def rep(old, new):
    global s
    n = s.count(old)
    assert n == 1, f"{n}x gefunden statt 1x:\n{old[:120]}"
    s = s.replace(old, new)

# 1. Konfig-Default
rep('''    "db_path": "/etc/pihole/pihole-FTL.db",
''', '''    "db_path": "/etc/pihole/pihole-FTL.db",
    "gravity_db": "/etc/pihole/gravity.db",   # Blocklisten; Beaconing dorthin = Tracker (Befund 46)
''')

# 2. Hilfsfunktion vor den Detections
rep('''def detect_beaconing(rows, cfg, allow, state, now, emit):
''', '''_GRAVITY = None


def gravity_listed(domain, cfg):
    """True, wenn die Domain oder eine Elterndomain auf einer Pi-hole-Blockliste steht
    (gravity) oder exakt in der Denylist. Clients, die am Blocking vorbei duerfen, sehen
    solche Domains im Takt der Werbeplaetze; das ist ein Tracker, kein C2 (Befund 46).
    Verbindung wird einmal geoeffnet; ohne gravity.db immer False."""
    global _GRAVITY
    if _GRAVITY is None:
        try:
            _GRAVITY = sqlite3.connect(f"file:{cfg['gravity_db']}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error:
            _GRAVITY = False
    if not _GRAVITY:
        return False
    parts = domain.split(".")
    cands = [".".join(parts[i:]) for i in range(max(1, len(parts) - 1))]
    q = ",".join("?" * len(cands))
    try:
        row = _GRAVITY.execute(
            f"SELECT 1 FROM gravity WHERE domain IN ({q}) "
            f"UNION SELECT 1 FROM domainlist WHERE type = 1 AND enabled = 1 AND domain IN ({q}) LIMIT 1",
            cands + cands).fetchone()
        return row is not None
    except sqlite3.Error:
        return False


def detect_beaconing(rows, cfg, allow, state, now, emit):
''')

# 3. Feld im Event
rep('''             regularity=round(regularity, 2),
''', '''             regularity=round(regularity, 2),
             tracker=gravity_listed(domain, cfg),
''')

assert s != orig
open(p, "w", encoding="utf-8").write(s)
print("ok:", p)
