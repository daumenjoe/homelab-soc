#!/usr/bin/env python3
"""
gen-architecture.py - Architekturdiagramm fuer das README, als SVG in hell und dunkel.

Aufruf:
    python3 docs/gen-architecture.py docs      # schreibt docs/architecture-{light,dark}.svg
    python3 docs/gen-architecture.py           # ins aktuelle Verzeichnis

Keine Flags, keine Abhaengigkeiten (nur Python 3). Beide Dateien kommen immer aus
derselben Vorlage; im README waehlt ein <picture>-Block die passende per
prefers-color-scheme.

Was wo angepasst wird - alles in render(), als Daten, nicht als Zeichenbefehle:

  Texte      sensors   = Liste (Titel, [zwei Zeilen]) je Sensorbox, links
             Wazuh-Zeilen in der for-Schleife direkt unter "Wazuh Manager"
             steps     = nummerierte Triage-Kette rechts
             box(...)  = IRIS, Grafana, Watchdog (Titel + Zeilen)
             Zahlen wie "100 rules" oder "13 hosts" stehen dort als Text.
  Farben     THEMES oben, je Theme ein Satz Hex-Werte. Schluessel: bg, fg,
             muted, box, line (Standard), hub (Wazuh), vr (Velociraptor),
             chain (Triage). Neue Farbe = neuer Schluessel in BEIDEN Themes.
  Positionen sx,sw,sh,gap,y0 Sensorspalte | hx,hy,hw,hh Wazuh |
             vx,vy,vw,vh EDR-Hop | rx,rw rechte Spalte | W,H Gesamtflaeche.
             Pfeile beziehen sich auf diese Variablen und wandern mit.
  Neue Box   links: Eintrag in sensors (Spalte waechst nach unten, H erhoehen).
             rechts: box(...) + arrow(...) Aufruf.

Kontrolle: SVG im Browser oeffnen, GitHub rendert identisch. Text, der ueber den
Boxrand laeuft, kuerzen oder Box verbreitern - es gibt keinen Zeilenumbruch.
"""
import sys, pathlib

THEMES = {
    "light": dict(bg="#ffffff", fg="#1f2328", muted="#57606a", box="#f6f8fa", line="#8c959f",
                  hub="#dbeafe", hubline="#1f6feb", chain="#fff8c5", chainline="#9a6700",
                  vr="#ddf4ff", vrline="#0969da"),
    "dark":  dict(bg="#0d1117", fg="#e6edf3", muted="#8b949e", box="#161b22", line="#6e7681",
                  hub="#0c2d6b", hubline="#58a6ff", chain="#3b2e00", chainline="#d29922",
                  vr="#0b2b47", vrline="#58a6ff"),
}

def box(x, y, w, h, title, lines, fill, stroke, c, bold_title=True, r=6):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>']
    ty = y + 18
    out.append(f'<text x="{x+12}" y="{ty}" font-size="13" font-weight="{"600" if bold_title else "400"}" fill="{c["fg"]}">{title}</text>')
    for l in lines:
        ty += 15
        out.append(f'<text x="{x+12}" y="{ty}" font-size="11.5" fill="{c["muted"]}">{l}</text>')
    return "\n".join(out)

def arrow(x1, y1, x2, y2, label, c, dashed=False, lx=None, ly=None, anchor="middle", color=None):
    col = color or c["line"]
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    s = f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="1.4"{dash} marker-end="url(#arr)"/>'
    if label:
        lx = lx if lx is not None else (x1 + x2) / 2
        ly = ly if ly is not None else (y1 + y2) / 2 - 6
        s += f'\n<text x="{lx}" y="{ly}" font-size="10.5" fill="{c["muted"]}" text-anchor="{anchor}">{label}</text>'
    return s

def render(c):
    W, H = 1300, 690
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="ui-sans-serif, system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif" role="img" aria-label="Data flow of the homelab SOC: six sensor types feed a Wazuh manager over the agent channel, Velociraptor clients report to their own server whose datastore is read by a local Wazuh agent, and alerts of level 7 and above pass through an enrichment and LLM triage chain into DFIR-IRIS; Grafana reads the alert index and a watchdog Pi checks all components.">',
         f'<rect width="{W}" height="{H}" fill="{c["bg"]}"/>',
         f'<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{c["line"]}"/></marker></defs>']

    # --- Spaltenueberschriften
    for x, t in ((20, "SENSORS"), (430, "EDR HOP"), (660, "SIEM"), (960, "RESPONSE / VIEW")):
        o.append(f'<text x="{x}" y="40" font-size="11" letter-spacing="1.5" fill="{c["muted"]}">{t}</text>')

    # --- Sensoren (links)
    sx, sw, sh, gap, y0 = 20, 290, 64, 12, 60
    sensors = [
        ("Pi-hole + Unbound  ·  Pi 4", ["DNS query log, SERVFAIL, analytics:", "beaconing · DGA · tunneling · NRD · hammering"]),
        ("Network sensor  ·  Pi 5", ["Suricata on switch mirror port (ET Open + local)", "Kismet WLAN (2.4 / 5 / 6 GHz, two radios)"]),
        ("OpenCanary honeypot  ·  LXC", ["SSH / HTTP / SMB decoys", "credential attempts, brute force, port touches"]),
        ("Fritzbox monitor", ["WAN / DHCP / WLAN events via TR-064", "dedup + counter suffix (Befund 17)"]),
        ("9 Linux hosts", ["auditd execve (firewall tools), FIM, journald,", "incl. redcanary VM = Atomic Red Team target"]),
        ("Velociraptor clients  ·  9 hosts", ["Homelab.Events.Baseline (ports, keys, cron)", "Homelab.Events.FirewallState (nft chains)"]),
    ]
    ys = []
    for i, (t, ls) in enumerate(sensors):
        y = y0 + i * (sh + gap)
        ys.append(y)
        fill, stroke = (c["vr"], c["vrline"]) if i == 5 else (c["box"], c["line"])
        o.append(box(sx, y, sw, sh, t, ls, fill, stroke, c))

    # --- Wazuh (Hub)
    hx, hy, hw, hh = 660, 60, 220, 444
    o.append(f'<rect x="{hx}" y="{hy}" width="{hw}" height="{hh}" rx="8" fill="{c["hub"]}" stroke="{c["hubline"]}" stroke-width="1.6"/>')
    o.append(f'<text x="{hx+16}" y="{hy+26}" font-size="15" font-weight="600" fill="{c["fg"]}">Wazuh Manager 4.14</text>')
    for j, l in enumerate(["single-node VM, 15 agents",
                           "",
                           "custom decoders + 100 rules",
                           "0100 Pi-hole · 0101 Unbound",
                           "0102 analytics · 0103 hw metrics",
                           "0105 honeypot · 0106 Fritzbox",
                           "0107 Kismet · 0108 Velociraptor",
                           "0900 Docker · 0910 Suricata",
                           "0920 auditd fw · 0930 AppArmor",
                           "",
                           "level ≥ 7 of the sensor groups",
                           "→ integration custom-iris",
                           "",
                           "alerts.json → wazuh-indexer",
                           "(OpenSearch)"]):
        o.append(f'<text x="{hx+16}" y="{hy+52+j*17}" font-size="11.5" fill="{c["muted"] if l and not l.startswith("level") and not l.startswith("→") else c["fg"]}">{l}</text>')

    # --- Velociraptor server (Hop)
    vx, vy, vw, vh = 430, hy + hh + 18, 190, 104
    o.append(box(vx, vy, vw, vh, "Velociraptor server  ·  LXC",
                 ["CLIENT_EVENT artifacts, 60 s",
                  "datastore: monitoring/*.json",
                  "read by the local Wazuh agent",
                  "(one localfile per source)"],
                 c["vr"], c["vrline"], c))

    # --- Pfeile Sensoren -> Wazuh (direkt, agent)
    labels = ["agent · query log + analytics json", "agent · eve.json + kismet json", "agent · opencanary log",
              "agent · monitor json", "agent · audit.log, syscheck, journald"]
    for i in range(5):
        y = ys[i] + sh / 2
        # Zielpunkt an Wazuh-Kante, leicht gefaechert
        ty = hy + 40 + i * 70
        o.append(arrow(sx + sw, y, hx, ty, labels[i], c, lx=(sx + sw + hx) / 2, ly=(y + ty) / 2 - 7))
    # Velociraptor: clients -> server -> wazuh
    y5 = ys[5] + sh / 2
    o.append(arrow(sx + sw, y5, vx, vy + vh / 2, "velociraptor client", c, color=c["vrline"], lx=(sx + sw + vx) / 2, ly=(y5 + vy + vh / 2) / 2 - 8))
    o.append(arrow(vx + vw, vy + 30, hx + 50, hy + hh, "agent · json localfile", c, color=c["vrline"],
                   lx=vx + vw + 8, ly=vy + 52, anchor="start"))

    # --- rechte Spalte
    rx, rw = 960, 320
    # IRIS
    o.append(box(rx, 60, rw, 64, "DFIR-IRIS  ·  case management", ["one case per alert, tags dm-* / llm-*", "enrichment and triage text attached"], c["box"], c["line"], c))
    # Kette
    ky, kh = 150, 230
    o.append(f'<rect x="{rx}" y="{ky}" width="{rw}" height="{kh}" rx="6" fill="{c["chain"]}" stroke="{c["chainline"]}" stroke-width="1.2"/>')
    o.append(f'<text x="{rx+12}" y="{ky+18}" font-size="13" font-weight="600" fill="{c["fg"]}">custom-iris v2.9  ·  enrichment + triage</text>')
    steps = [("1", "RDAP", "domain age"),
             ("2", "VirusTotal", "quota-limited, cached"),
             ("3", "MISP", "restSearch + feed cache, decay"),
             ("4", "nimble", "decision model, gate 0.5"),
             ("5", "Gemma 4 12B", "triage if needs_human ≥ 0.5"),
             ("6", "gpt-oss 20B", "second opinion → llm-disagree")]
    for j, (n, name, what) in enumerate(steps):
        yy = ky + 42 + j * 30
        o.append(f'<circle cx="{rx+22}" cy="{yy-4}" r="9" fill="{c["bg"]}" stroke="{c["chainline"]}" stroke-width="1.2"/>')
        o.append(f'<text x="{rx+22}" y="{yy}" font-size="10.5" font-weight="600" text-anchor="middle" fill="{c["fg"]}">{n}</text>')
        o.append(f'<text x="{rx+40}" y="{yy}" font-size="12" font-weight="600" fill="{c["fg"]}">{name}</text>')
        o.append(f'<text x="{rx+140}" y="{yy}" font-size="11" fill="{c["muted"]}">{what}</text>')
    o.append(f'<text x="{rx+12}" y="{ky+kh-10}" font-size="10.5" fill="{c["muted"]}">Ollama on a separate PC, port 11434 only for the manager</text>')
    # Grafana
    o.append(box(rx, 410, rw, 64, "Grafana + Prometheus  ·  LXC", ["Wazuh Alerts dashboard (OpenSearch, read-only)", "node / pihole / fritzbox exporters on 13 hosts"], c["box"], c["line"], c))
    # Watchdog
    o.append(box(rx, 500, rw, 64, "Watchdog  ·  Pi 3", ["14 checks: services, backups, NIC, alert volume", "ntfy push on state change, outside the stack"], c["box"], c["line"], c))

    # Pfeile Wazuh -> rechts
    o.append(arrow(hx + hw, hy + 230, rx, ky + 60, "level ≥ 7", c, color=c["chainline"], lx=hx + hw + 6, ly=hy + 230 + 16, anchor="start"))
    o.append(arrow(rx + 150, ky, rx + 150, 124, "case + tags", c, color=c["chainline"], lx=rx + 158, ly=140, anchor="start"))
    o.append(arrow(hx + hw, hy + 400, rx, 442, "OpenSearch", c, lx=hx + hw + 4, ly=hy + 400 + 16, anchor="start"))
    o.append(arrow(rx, 532, hx + hw, hy + hh - 12, "HTTP / TCP checks", c, dashed=True, lx=rx - 8, ly=532 + 16, anchor="end"))

    # Fussnote
    o.append(f'<text x="20" y="{H-18}" font-size="10.5" fill="{c["muted"]}">Proxmox PVE 9 on a Lenovo M90q (i5-10500, 32 GB) hosts the VMs and LXCs; Pis, the LLM PC and the switch mirror port are separate hardware. All hosts are in Wazuh, Velociraptor and Prometheus.</text>')
    o.append("</svg>")
    return "\n".join(o)

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
out.mkdir(parents=True, exist_ok=True)
for name, c in THEMES.items():
    (out / f"architecture-{name}.svg").write_text(render(c), encoding="utf-8")
    print("wrote", out / f"architecture-{name}.svg")
