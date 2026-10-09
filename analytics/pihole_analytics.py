#!/usr/bin/env python3
"""
pihole_analytics.py - behavioural DNS analytics on Pi-hole FTL data for Wazuh.

Runs periodically (systemd timer), reads /etc/pihole/pihole-FTL.db read-only,
and writes JSON-lines events to a log file that the Wazuh agent ingests with
<log_format>json</log_format>.

Detections
  beaconing       fixed-interval queries from one client to one domain
  dga             high-entropy / consonant-heavy / digit-heavy registrable label
  nxdomain_ratio  one client producing many NXDOMAIN for distinct domains
  nrd             registrable domain found in a newly-registered-domains list
  tunneling       one client, one domain, many DIFFERENT long subdomains (data in names)
  blocked_hammering  one client hammering one blocked registrable domain (retry loop, no backoff)
  correlation     nrd plus dga, beaconing and/or tunneling for the same client and domain
  heartbeat       one event per run with counters (job liveness)

Only the Python standard library is required. If `tldextract` is installed
the registrable domain (eTLD+1) is derived from the Public Suffix List,
otherwise a small built-in fallback is used.
"""

import json
import logging
import math
import os
import sqlite3
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.4.0"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULTS = {
    "db_path": "/etc/pihole/pihole-FTL.db",
    "log_path": "/var/log/pihole-analytics/analytics.log",
    "state_path": "/var/lib/pihole-analytics/state.json",
    "allowlist_path": "/etc/pihole-analytics/allowlist.txt",
    "nrd_path": "/var/lib/pihole-analytics/nrd.db",
    # Domains never analysed (suffix match, case-insensitive)
    "ignore_suffixes": [".in-addr.arpa", ".ip6.arpa", ".local", ".lan",
                        ".fritz.box", ".home.arpa"],
    # Clients never analysed (exact match on the client string in FTL)
    "ignore_clients": [],
    # How far back to scan on the very first run / after state loss
    "max_lookback_seconds": 86400,
    "beacon": {
        "window_seconds": 21600,      # 6 h sliding window
        "burst_gap_seconds": 2,       # A/AAAA/HTTPS triplets collapse to one event
        "min_events": 12,
        "min_duration_seconds": 3600,  # a pattern must persist; page-driven ad refresh does not
        "min_interval": 15,
        "max_interval": 3600,
        "max_jitter": 0.15,           # MAD / median of intervals
        "min_regularity": 0.80,       # share of intervals within +-20 % of median
        "cooldown_seconds": 21600,
    },
    "dga": {
        "min_label_length": 10,
        "min_entropy": 3.5,
        "max_vowel_ratio": 0.20,
        "min_digit_ratio": 0.30,
        "consonant_run": 5,
        "min_score": 3,
        "cooldown_seconds": 86400,
    },
    "nxdomain": {
        "min_unique": 20,
        "min_ratio": 0.30,
        "cooldown_seconds": 3600,
    },
    "nrd": {
        "include_blocked": True,
        "cooldown_seconds": 86400,
    },
    "tunnel": {
        # Thresholds from a 24 h baseline of real traffic (2026-09-21): busiest benign
        # pair had 49 unique long subdomains, 1805 chars, new-name ratio 0.33.
        "min_subdomain_length": 20,   # subdomain part (without registrable domain)
        "min_unique": 60,             # distinct long subdomains in the window
        "min_payload_chars": 2500,    # summed length of those subdomains
        "min_new_ratio": 0.4,         # distinct names / queries; browsers ask A+AAAA+HTTPS = 0.33
        "cooldown_seconds": 21600,
    },
    "hammering": {
        # One client asking the same BLOCKED registrable domain min_blocked times
        # in the window AND at >= min_rate_per_min over its active span (first to
        # last hit). Both together: 100 blocks spread over 6 h is app behaviour,
        # 100 blocks in 10 minutes is a retry loop without backoff (Befund 35).
        # Aggregated on the registrable domain because telemetry SDKs (conviva)
        # rotate the subdomain per session. Not a security signal: does not feed
        # the correlation. It names the client the dnsmasq block line lacks.
        "min_blocked": 100,
        "min_rate_per_min": 2.0,
        "min_span_seconds": 60,       # below one minute of span no rate is meaningful
        "cooldown_seconds": 21600,
    },
    "correlation": {
        "window_seconds": 604800,     # signals older than 7 d no longer combine
        "cooldown_seconds": 86400,
    },
}

# Pi-hole FTL enumerations (v5.x / v6.x)
QUERY_TYPES = {1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR",
               7: "TXT", 8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG",
               12: "DNSKEY", 13: "NS", 14: "OTHER", 15: "SVCB", 16: "HTTPS"}
# status values that mean "blocked" (gravity, regex, denylist, their CNAME
# variants, upstream blocks incl. EDE15, database busy, special domain).
# NOT blocked: 2 forwarded, 3 cache, 12-14 retried/in progress, and 17 =
# answered from STALE cache - counting 17 as blocked was a bug up to 1.2.0.
BLOCKED_STATUS = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}
REPLY_NXDOMAIN = 2

VOWELS = set("aeiouy")
CONSONANTS = set("bcdfghjklmnpqrstvwxz")


def deep_merge(base, override):
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path):
    cfg = DEFAULTS
    if path and Path(path).is_file():
        with open(path, encoding="utf-8") as fh:
            cfg = deep_merge(DEFAULTS, json.load(fh))
    return cfg


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------

try:
    import tldextract  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    tldextract = None

_EXTRACT = None


def init_tldextract(cache_dir):
    """Enable Public-Suffix-List based parsing if tldextract works.

    1. bundled snapshot (pip installs ship it, Debian's python3-tldextract
       does not),
    2. a PSL copy fetched once into cache_dir (needs network on first run),
    3. otherwise the built-in fallback list is used.
    tldextract loads its data lazily, so each candidate is exercised once."""
    global _EXTRACT
    if tldextract is None:
        return False
    candidates = [
        dict(suffix_list_urls=(), fallback_to_snapshot=True),
        dict(cache_dir=str(cache_dir)),
    ]
    for kwargs in candidates:
        try:
            ext = tldextract.TLDExtract(**kwargs)
            probe = ext("www.example.co.uk")
            if probe.domain == "example" and probe.suffix == "co.uk":
                _EXTRACT = ext
                return True
        except Exception as exc:
            logging.warning("tldextract init failed (%s): %s", kwargs, exc)
    return False


_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.cn",
    "com.tr", "co.za", "co.in", "com.mx", "com.ar", "co.kr", "com.sg",
    "com.hk", "com.tw", "co.il", "com.ua", "com.pl",
}


def normalise(fqdn):
    return fqdn.rstrip(".").lower()


def registrable(fqdn):
    """Return (registrable_domain, main_label) e.g. ('example.co.uk', 'example')."""
    fqdn = normalise(fqdn)
    if _EXTRACT is not None:
        e = _EXTRACT(fqdn)
        if e.domain and e.suffix:
            return f"{e.domain}.{e.suffix}", e.domain
        return fqdn, fqdn.split(".")[0]
    labels = fqdn.split(".")
    if len(labels) < 2:
        return fqdn, fqdn
    if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL:
        return ".".join(labels[-3:]), labels[-3]
    return ".".join(labels[-2:]), labels[-2]


def shannon_entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def longest_consonant_run(s):
    best = run = 0
    for ch in s:
        run = run + 1 if ch in CONSONANTS else 0
        best = max(best, run)
    return best


class Allowlist:
    """Lines: '#' comments, '.suffix' for suffix match, otherwise exact match
    on either the FQDN or the registrable domain."""

    def __init__(self, path):
        self.exact = set()
        self.suffixes = []
        p = Path(path)
        if not p.is_file():
            return
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith("."):
                self.suffixes.append(line)
            else:
                self.exact.add(line.rstrip("."))

    def allows(self, fqdn, regdom):
        if fqdn in self.exact or regdom in self.exact:
            return True
        return any(fqdn.endswith(s) or fqdn == s[1:] for s in self.suffixes)


class NrdLookup:
    """Membership test for registrable domains against an NRD list.

    Backed by a SQLite table (built with `import-nrd`), so lookups are index
    hits and memory stays flat even for 30-day lists with >10 M entries.
    A plain-text file is still accepted for small lists / testing."""

    def __init__(self, path):
        self.path = Path(path)
        self.conn = None
        self.entries = None
        self.meta = {}
        if not self.path.is_file():
            return
        if self.path.suffix == ".db":
            self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
            try:
                self.meta = dict(self.conn.execute("SELECT key, value FROM meta"))
            except sqlite3.OperationalError:
                self.meta = {}
        else:
            self.entries = set()
            with open(self.path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.entries.add(line.rstrip("."))

    def __len__(self):
        if self.conn is not None:
            return int(self.meta.get("count", 0))
        return len(self.entries or ())

    def __contains__(self, regdom):
        if self.conn is not None:
            return self.conn.execute(
                "SELECT 1 FROM nrd WHERE domain = ? LIMIT 1", (regdom,)).fetchone() is not None
        return bool(self.entries) and regdom in self.entries

    def close(self):
        if self.conn is not None:
            self.conn.close()


def import_nrd(src, dst, source_url=""):
    """Build the NRD SQLite database from a plain-text list (one domain per line).
    Writes to a temp file and swaps atomically so a running analysis never sees
    a half-written database."""
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    conn = sqlite3.connect(tmp)
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("CREATE TABLE nrd (domain TEXT PRIMARY KEY) WITHOUT ROWID")
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    count = 0
    batch = []
    with open(src, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
                line = line.split()[1]
            line = line.lstrip("|").rstrip("^").rstrip(".")
            if "." not in line:
                continue
            batch.append((line,))
            if len(batch) >= 50000:
                conn.executemany("INSERT OR IGNORE INTO nrd VALUES (?)", batch)
                count += len(batch)
                batch.clear()
    if batch:
        conn.executemany("INSERT OR IGNORE INTO nrd VALUES (?)", batch)
        count += len(batch)
    real = conn.execute("SELECT COUNT(*) FROM nrd").fetchone()[0]
    conn.executemany("INSERT INTO meta VALUES (?, ?)", [
        ("count", str(real)),
        ("imported_at", time.strftime("%Y-%m-%dT%H:%M:%S%z")),
        ("source", source_url),
    ])
    conn.commit()
    conn.close()
    os.replace(tmp, dst)
    return real


# --------------------------------------------------------------------------
# State & output
# --------------------------------------------------------------------------

class State:
    def __init__(self, path):
        self.path = Path(path)
        self.data = {"last_id": 0, "alerts": {}}
        if self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                logging.warning("state file unreadable, starting fresh")

    @property
    def last_id(self):
        return int(self.data.get("last_id", 0))

    @last_id.setter
    def last_id(self, value):
        self.data["last_id"] = int(value)

    def in_cooldown(self, key, now, cooldown):
        last = self.data["alerts"].get(key)
        return last is not None and now - last < cooldown

    def mark(self, key, now):
        self.data["alerts"][key] = now

    def note_signal(self, client, regdom, signal, now):
        """Remember that <client> showed <signal> for <regdom>. Independent of
        alert cooldowns: those are keyed per domain, so a second client would
        otherwise leave no trace for the correlation."""
        sig = self.data.setdefault("signals", {})
        sig.setdefault(f"{client}|{regdom}", {})[signal] = now

    def prune(self, now, max_age=7 * 86400):
        self.data["alerts"] = {k: v for k, v in self.data["alerts"].items()
                               if now - v < max_age}
        kept = {}
        for pair, sig in self.data.get("signals", {}).items():
            fresh = {k: v for k, v in sig.items() if now - v < max_age}
            if fresh:
                kept[pair] = fresh
        self.data["signals"] = kept

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data), encoding="utf-8")
        os.replace(tmp, self.path)


class Emitter:
    def __init__(self, log_path):
        self.path = Path(log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.count = Counter()
        self._buf = []

    def emit(self, detection, **fields):
        event = {"pihole_analytics": {
            "version": VERSION,
            "detection": detection,
            "event_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            **fields,
        }}
        self._buf.append(json.dumps(event, ensure_ascii=False))
        self.count[detection] += 1

    def flush(self):
        """Alle gepufferten Events in einem Rutsch dauerhaft schreiben."""
        if not self._buf:
            return
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(self._buf) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._buf.clear()

    def close(self):
        self.flush()


# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------

def detect_beaconing(rows, cfg, allow, state, now, emit):
    c = cfg["beacon"]
    series = defaultdict(list)
    blocked = defaultdict(int)
    for ts, status, domain, client in rows:
        d = normalise(domain)
        regdom, _ = registrable(d)
        if allow.allows(d, regdom):
            continue
        series[(client, d)].append(int(ts))
        if status in BLOCKED_STATUS:
            blocked[(client, d)] += 1

    for (client, domain), tss in series.items():
        tss.sort()
        collapsed = [tss[0]]
        for t in tss[1:]:
            if t - collapsed[-1] > c["burst_gap_seconds"]:
                collapsed.append(t)
        if len(collapsed) < c["min_events"]:
            continue
        if collapsed[-1] - collapsed[0] < c["min_duration_seconds"]:
            continue
        intervals = [b - a for a, b in zip(collapsed, collapsed[1:])]
        med = statistics.median(intervals)
        if not (c["min_interval"] <= med <= c["max_interval"]):
            continue
        mad = statistics.median(abs(i - med) for i in intervals)
        jitter = mad / med if med else 1.0
        regularity = sum(1 for i in intervals if abs(i - med) <= 0.2 * med) / len(intervals)
        if jitter > c["max_jitter"] or regularity < c["min_regularity"]:
            continue

        state.note_signal(client, registrable(domain)[0], "beaconing", now)
        key = f"beaconing|{client}|{domain}"
        if state.in_cooldown(key, now, c["cooldown_seconds"]):
            continue
        state.mark(key, now)
        emit("beaconing",
             client=client,
             domain=domain,
             registrable=registrable(domain)[0],
             events=len(collapsed),
             raw_queries=len(tss),
             median_interval=round(med, 1),
             jitter=round(jitter, 3),
             regularity=round(regularity, 2),
             score=round(regularity * (1 - jitter), 2),
             blocked_queries=blocked.get((client, domain), 0),
             duration_seconds=collapsed[-1] - collapsed[0],
             first_seen=collapsed[0],
             last_seen=collapsed[-1],
             window_seconds=c["window_seconds"])


def dga_features(label):
    n = len(label)
    if n == 0:
        return None
    letters = [ch for ch in label if ch.isalpha()]
    vowel_ratio = (sum(1 for ch in letters if ch in VOWELS) / len(letters)) if letters else 0.0
    return {
        "length": n,
        "entropy": round(shannon_entropy(label), 3),
        "vowel_ratio": round(vowel_ratio, 2),
        "digit_ratio": round(sum(ch.isdigit() for ch in label) / n, 2),
        "consonant_run": longest_consonant_run(label),
    }


def detect_dga_and_nrd(rows, cfg, allow, nrd, state, now, emit):
    dc, nc, xc = cfg["dga"], cfg["nrd"], cfg["nxdomain"]
    nx_by_client = defaultdict(set)
    total_by_client = Counter()

    for qid, ts, qtype, status, domain, client, reply_type in rows:
        d = normalise(domain)
        regdom, label = registrable(d)
        total_by_client[client] += 1
        if reply_type == REPLY_NXDOMAIN:
            nx_by_client[client].add(d)
        if allow.allows(d, regdom):
            continue
        is_blocked = status in BLOCKED_STATUS

        # --- NRD -------------------------------------------------------
        if regdom in nrd and (nc["include_blocked"] or not is_blocked):
            state.note_signal(client, regdom, "nrd", now)
            key = f"nrd|{regdom}"
            if not state.in_cooldown(key, now, nc["cooldown_seconds"]):
                state.mark(key, now)
                emit("nrd", client=client, domain=d, registrable=regdom,
                     qtype=QUERY_TYPES.get(qtype, str(qtype)),
                     blocked=is_blocked, query_time=int(ts))

        # --- DGA heuristic on the registrable label -------------------
        f = dga_features(label)
        if not f or f["length"] < dc["min_label_length"]:
            continue
        reasons = []
        if f["entropy"] >= dc["min_entropy"]:
            reasons.append("entropy")
        if f["vowel_ratio"] <= dc["max_vowel_ratio"]:
            reasons.append("low_vowels")
        if f["digit_ratio"] >= dc["min_digit_ratio"]:
            reasons.append("digits")
        if f["consonant_run"] >= dc["consonant_run"]:
            reasons.append("consonant_run")
        if reply_type == REPLY_NXDOMAIN:
            reasons.append("nxdomain")
        if len(reasons) < dc["min_score"]:
            continue
        state.note_signal(client, regdom, "dga", now)
        key = f"dga|{regdom}"
        if state.in_cooldown(key, now, dc["cooldown_seconds"]):
            continue
        state.mark(key, now)
        emit("dga", client=client, domain=d, registrable=regdom, label=label,
             qtype=QUERY_TYPES.get(qtype, str(qtype)), blocked=is_blocked,
             score=len(reasons), reasons=reasons, query_time=int(ts), **f)

    # --- NXDOMAIN ratio per client ------------------------------------
    for client, nx in nx_by_client.items():
        total = total_by_client[client]
        ratio = len(nx) / total if total else 0.0
        if len(nx) < xc["min_unique"] or ratio < xc["min_ratio"]:
            continue
        key = f"nxdomain_ratio|{client}"
        if state.in_cooldown(key, now, xc["cooldown_seconds"]):
            continue
        state.mark(key, now)
        emit("nxdomain_ratio", client=client, nxdomain_unique=len(nx),
             queries_total=total, ratio=round(ratio, 2),
             sample=sorted(nx)[:10])


def detect_tunneling(rows, cfg, allow, state, now, emit):
    """DNS tunnelling / exfiltration carries its payload in the query name, so
    every name is new. Benign look-alikes either repeat one long label
    (telemetry) or stay far below these volumes (ad hashes)."""
    c = cfg["tunnel"]
    total = Counter()
    names = defaultdict(set)
    for ts, status, domain, client in rows:
        d = normalise(domain)
        regdom, _ = registrable(d)
        if not d.endswith("." + regdom) or allow.allows(d, regdom):
            continue
        total[(client, regdom)] += 1
        names[(client, regdom)].add(d[:-len(regdom) - 1])

    for (client, regdom), subs in names.items():
        long_subs = [s for s in subs if len(s) >= c["min_subdomain_length"]]
        if len(long_subs) < c["min_unique"]:
            continue
        payload = sum(len(s) for s in long_subs)
        ratio = len(subs) / total[(client, regdom)]
        if payload < c["min_payload_chars"] or ratio < c["min_new_ratio"]:
            continue
        state.note_signal(client, regdom, "tunneling", now)
        key = f"tunneling|{client}|{regdom}"
        if state.in_cooldown(key, now, c["cooldown_seconds"]):
            continue
        state.mark(key, now)
        emit("tunneling", client=client, registrable=regdom,
             unique_long=len(long_subs), unique_subdomains=len(subs),
             queries=total[(client, regdom)], payload_chars=payload,
             avg_length=round(payload / len(long_subs), 1), new_ratio=round(ratio, 2),
             sample=[s[:60] for s in sorted(long_subs, key=len, reverse=True)[:3]],
             window_seconds=cfg["beacon"]["window_seconds"])


def detect_blocked_hammering(rows, cfg, allow, state, now, emit):
    """A device (or an SDK inside it) that does not accept a DNS block as an
    answer and retries in a tight loop. Floods the SIEM (Befund 35: 70 % of
    daily volume from one smart TV) and can reveal a device in network standby
    that is never really off. Noise, not an attack - hence no note_signal()."""
    c = cfg["hammering"]
    per = defaultdict(lambda: {"n": 0, "first": None, "last": None, "fqdns": Counter()})
    for ts, status, domain, client in rows:
        if status not in BLOCKED_STATUS:
            continue
        d = normalise(domain)
        regdom, _ = registrable(d)
        if allow.allows(d, regdom):
            continue
        ts = int(ts)
        e = per[(client, regdom)]
        e["n"] += 1
        e["first"] = ts if e["first"] is None else min(e["first"], ts)
        e["last"] = ts if e["last"] is None else max(e["last"], ts)
        e["fqdns"][d] += 1

    for (client, regdom), e in per.items():
        if e["n"] < c["min_blocked"]:
            continue
        span = e["last"] - e["first"]
        if span < c["min_span_seconds"]:
            continue
        rate = e["n"] / (span / 60.0)
        if rate < c["min_rate_per_min"]:
            continue
        key = f"hammering|{client}|{regdom}"
        if state.in_cooldown(key, now, c["cooldown_seconds"]):
            continue
        state.mark(key, now)
        top_fqdn, top_n = e["fqdns"].most_common(1)[0]
        emit("blocked_hammering",
             client=client,
             registrable=regdom,
             blocked_queries=e["n"],
             distinct_fqdns=len(e["fqdns"]),
             top_fqdn=top_fqdn,
             top_fqdn_queries=top_n,
             rate_per_min=round(rate, 1),
             span_seconds=span,
             first_seen=e["first"],
             last_seen=e["last"],
             window_seconds=cfg["beacon"]["window_seconds"])


def detect_correlation(cfg, state, now, emit):
    """A newly registered domain that ALSO looks generated or is contacted at
    fixed intervals by the same client. Each signal alone is mostly benign;
    together they are a strong indicator."""
    c = cfg["correlation"]
    for pair, sig in state.data.get("signals", {}).items():
        fresh = {k: v for k, v in sig.items() if now - v <= c["window_seconds"]}
        if "nrd" not in fresh or not ({"dga", "beaconing", "tunneling"} & fresh.keys()):
            continue
        combo = "+".join(sorted(fresh))
        key = f"correlation|{pair}|{combo}"   # a new combination alerts again
        if state.in_cooldown(key, now, c["cooldown_seconds"]):
            continue
        state.mark(key, now)
        client, regdom = pair.split("|", 1)
        emit("correlation", client=client, registrable=regdom,
             signals=combo, signal_count=len(fresh),
             **{f"{k}_seen": v for k, v in fresh.items()})


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def should_skip(domain, client, cfg):
    d = normalise(domain)
    if client in cfg["ignore_clients"]:
        return True
    # Single labels are unqualified hostnames (search-domain lookups) or
    # dnsmasq placeholders such as "opcode" for non-query packets - neither can
    # reach the internet, so they carry no signal for these detections.
    if "." not in d:
        return True
    return any(d.endswith(s) for s in cfg["ignore_suffixes"])


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg_path = os.environ.get("PIHOLE_ANALYTICS_CONFIG", "/etc/pihole-analytics/config.json")
    cfg = load_config(cfg_path)
    now = int(time.time())
    started = time.monotonic()

    state = State(cfg["state_path"])
    init_tldextract(Path(cfg["state_path"]).parent / "psl-cache")
    allow = Allowlist(cfg["allowlist_path"])
    nrd = NrdLookup(cfg["nrd_path"])
    emit = Emitter(cfg["log_path"])

    try:
        conn = sqlite3.connect(f"file:{cfg['db_path']}?mode=ro", uri=True, timeout=15)
        conn.execute("PRAGMA query_only = 1")

        # New, not yet analysed queries (per-query detections)
        lookback = now - cfg["max_lookback_seconds"]
        new_rows = conn.execute(
            "SELECT id, timestamp, type, status, domain, client, reply_type "
            "FROM queries WHERE id > ? AND timestamp >= ? ORDER BY id",
            (state.last_id, lookback)).fetchall()
        new_rows = [r for r in new_rows if not should_skip(r[4], r[5], cfg)]

        # Sliding window for interval analysis
        win_rows = conn.execute(
            "SELECT timestamp, status, domain, client FROM queries "
            "WHERE timestamp >= ? ORDER BY timestamp",
            (now - cfg["beacon"]["window_seconds"],)).fetchall()
        win_rows = [r for r in win_rows if not should_skip(r[2], r[3], cfg)]
        conn.close()

        detect_dga_and_nrd(new_rows, cfg, allow, nrd, state, now, emit.emit)
        detect_beaconing(win_rows, cfg, allow, state, now, emit.emit)
        detect_tunneling(win_rows, cfg, allow, state, now, emit.emit)
        detect_blocked_hammering(win_rows, cfg, allow, state, now, emit.emit)
        detect_correlation(cfg, state, now, emit.emit)

        if new_rows:
            state.last_id = max(r[0] for r in new_rows)
        state.prune(now)

        emit.emit("heartbeat",
                  queries_new=len(new_rows),
                  queries_window=len(win_rows),
                  nrd_entries=len(nrd),
                  allowlist_entries=len(allow.exact) + len(allow.suffixes),
                  tldextract=_EXTRACT is not None,
                  findings={k: v for k, v in emit.count.items() if k != "heartbeat"},
                  runtime_ms=int((time.monotonic() - started) * 1000))
        # Reihenfolge ist Absicht: erst Findings auf die Platte, dann State.
        # Abbruch dazwischen = doppelter Alert im nächsten Lauf (harmlos),
        # umgekehrt wäre es ein verlorener Alert plus Cooldown (nicht harmlos).
        emit.flush()
        state.save()
        logging.info("done: new=%d window=%d findings=%s",
                     len(new_rows), len(win_rows), dict(emit.count))
    except sqlite3.OperationalError as exc:
        emit.emit("error", message=f"sqlite: {exc}")
        logging.error("sqlite error: %s", exc)
        return 1
    finally:
        emit.close()
        nrd.close()
    return 0


def cli():
    if len(sys.argv) >= 3 and sys.argv[1] == "import-nrd":
        src = sys.argv[2]
        dst = sys.argv[3] if len(sys.argv) >= 4 else DEFAULTS["nrd_path"]
        url = os.environ.get("NRD_URL", "")
        n = import_nrd(src, dst, url)
        print(f"imported {n} domains into {dst}")
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] not in ("run",):
        print("usage: pihole_analytics.py [run] | import-nrd <list.txt> [nrd.db]", file=sys.stderr)
        return 2
    return main()


if __name__ == "__main__":
    sys.exit(cli())
