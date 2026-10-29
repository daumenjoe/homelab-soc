# Homelab SOC

Detection engineering on a mini PC. Six sensor types feed a Wazuh SIEM,
alerts of level 7 and up are enriched (RDAP, VirusTotal, MISP), triaged by
local LLMs and filed as DFIR-IRIS cases. Every detection was tested against
the attack technique, not against the rule. Hardware: one Lenovo M90q, three
Raspberry Pis, one desktop with a consumer GPU. Running daily since September
2026. Mistakes are in [TUNING.md](TUNING.md).

<!-- docs/dashboard.png: Grafana "Wazuh Alerts", 24 h view, browser chrome cropped -->
![Grafana dashboard: alerts per hour, today's count, top rules, level-10 alerts](docs/dashboard.png)

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.svg">
  <img alt="Data flow: six sensor types feed Wazuh over the agent channel; Velociraptor clients report to their own server, whose datastore a local Wazuh agent reads; alerts of level 7 and above pass through enrichment and LLM triage into DFIR-IRIS; Grafana reads the alert index; a watchdog Pi checks every component from outside." src="docs/architecture-light.svg" width="100%">
</picture>

| Component | Role | Runs on |
|---|---|---|
| Wazuh 4.14 | SIEM: decoders, ~110 custom rules, 16 agents, indexer | VM |
| Pi-hole 6 + Unbound | recursive DNS with blocklists; the query log is the DNS sensor | Raspberry Pi 4 |
| Suricata 8 + Kismet | IDS on a switch mirror port; WLAN monitoring on two radios | Raspberry Pi 5 |
| OpenCanary | honeypot, decoys for SSH/HTTP/SMB/Redis/VNC; no outbound except SIEM, DNS and the apt cache | LXC |
| Velociraptor 0.77 | EDR: baseline and firewall-state artifacts on all Linux hosts | LXC + 9 clients |
| auditd | execve auditing of firewall tools on the attack target | redcanary VM |
| DFIR-IRIS 2.4 | case management; one case per alert of level ≥ 7 from the sensor groups (Pi-hole, Suricata, honeypot, Velociraptor). Wazuh's own rootcheck/FIM/PAM alerts stay in the SIEM | VM |
| MISP 2.5 | threat intelligence, queried with decay scoring | VM |
| Ollama | nimble (gate), Gemma 4 12B (triage), cogito 32B (second opinion). The PC is off most of the day; cases are queued and triaged when it is on | separate PC, RX 7900 XT |
| Grafana + Prometheus | alert dashboard on the OpenSearch index; host, Pi-hole, Fritzbox and power metrics | LXC |
| Watchdog | 15 liveness checks with ntfy push, outside the stack | Raspberry Pi 3 |
| apt-cacher-ng | package cache for all hosts; the honeypot's only route to the mirrors | LXC |
| Proxmox PVE 9 | hypervisor; nightly backups to SSD, weekly to a USB disk | Lenovo M90q |

Velociraptor clients report to their own server. The Wazuh agent on that
server reads the datastore as JSON files. That bridge was lost once without
anyone noticing (finding 32).

## What gets detected

Tested with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
on a throwaway VM (`redcanary`, snapshot reset between runs) or against the
honeypot. "Detected" means: alert in Wazuh and, for level ≥ 7, a case in IRIS.

| ATT&CK | Technique | Sensor | Rule | Result |
|---|---|---|---|---|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron job | Velociraptor `Homelab.Events.Baseline` | 110183 | detected |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH authorized_keys | Velociraptor `Homelab.Events.Baseline` | 110182 | detected (Atomic test 1 only checks write access; tested with a real key) |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS to an external resolver (Pi-hole bypass) | Suricata, local rule on the mirror port | 110166 | detected, real time |
| [T1110](https://attack.mitre.org/techniques/T1110/) | SSH brute force | OpenCanary | 110133 / 110134 | detected, mail + IRIS case |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local account created | Wazuh journald | 5902 | detected after fixing a gap: the agent lacked the `systemd-journal` group on every modern host (finding 26) |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network service discovery | OpenCanary | 110132 | detected via decoy touches; no port-scan alert (no iptables logging in an unprivileged LXC) |
| [T1562.004](https://attack.mitre.org/techniques/T1562/004/) | Disable or modify system firewall | auditd execve on `nft`/`iptables`/`ufw`; Velociraptor `Homelab.Events.FirewallState` (chain set) | 110190 / 110191; 110184 / 110185 | detected on both paths: `nft flush` → L12 via auditd, `ufw disable` → L12 via chain-set diff. The state monitor also sees changes made via Netlink or a renamed binary |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File deletion in `/tmp` | | | **not detected.** FIM covers `/etc` and `/usr/bin`; `/tmp` is left out on purpose (churn) |

Two tests found gaps that the configuration did not show: the
`systemd-journal` group (T1136.001) and a datastore ACL that locked the Wazuh
agent out of Velociraptor results (finding 25).

The Pi-hole analytics detectors (beaconing, DGA, DNS tunneling,
newly-registered domains, blocked-domain hammering) are tuned on a 24 h
baseline and checked with synthetic cases. The Suricata chain was verified
with a known-bad user agent sent from the LAN.

## Broken while green

Four cases, each with a full write-up in TUNING.md.

**A sensor that never reached the SIEM.** A volume review after a sensor
rebuild showed no Velociraptor hits at all. Nine clients were reporting to
their server; nothing carried the results to Wazuh. The bridge had existed and
had been overwritten by a config sync. Rebuilt as a per-source `localfile` in
an agent group, verified with a live test.
→ [case study](case-studies/velociraptor-bridge.md), findings 32 and 34

**One TV, 70 % of all alerts.** Alert count tripled for three days. 3,300 of
4,800 alerts were Pi-hole blocks from one Android TV in network standby,
retrying blocked telemetry domains without back-off. Fix on both sides: a
frequency rule turns the retry loop into one event, an analytics detector
names the client (the dnsmasq block line does not carry it), two standby
settings on the TV ended the night traffic. → finding 35

```
Pi-hole blocks per hour, 2026-10-09, before the fix
04:xx   221  ###
10:xx   226  ###
12:xx   783  ###########
13:xx   429  ######
15:xx   442  ######
   …  the TV was on for about ten minutes that day
```

**The bridge dropped the first event of every day.** Velociraptor writes one
file per client, source and day. The Wazuh agent reads those files by
wildcard and starts at the end of any file it discovers at runtime, so the
event that created the file was lost, with the rest of its burst.
`only-future-events` did not help; reproduced three times. The Atomic tests
had passed because earlier tests had created the day's files. Fix: a
heartbeat row per artifact source just after midnight UTC. → finding 39

**The triage pipeline alerting on itself.** The listening-port baseline
reported the ephemeral ports Ollama opens per model run, which were caused by
the triage of the previous alert. Closed with a port filter on the artifact.
→ finding 27

## Tools in this repo

| | |
|---|---|
| [`analytics/pihole_analytics.py`](analytics/pihole_analytics.py) | DNS analytics on the Pi-hole FTL database: beaconing (interval regularity), DGA features, DNS tunneling (payload in subdomains), newly-registered domains, blocked-domain hammering, correlation. Standard library only, state file, heartbeat event |
| [`velociraptor/`](velociraptor/) | two CLIENT_EVENT artifacts: `Homelab.Events.Baseline` (new listening ports, SSH keys, cron lines via `diff()`), `Homelab.Events.FirewallState` (nftables chain set from `nft -j`; catches `ufw disable`, `nft flush`, Docker and iptables-nft changes) |
| [`integrations/custom-iris.py`](integrations/) | Wazuh integration: RDAP → VirusTotal → MISP (decay) → decision model gate → LLM triage → second opinion → IRIS case with tags. The prompt carries the network's own infrastructure hosts (finding 42) |
| [`integrations/triage-spooler.py`](integrations/) | LLM host off: the IRIS case is created at once, the case is spooled, a systemd timer polls the Ollama API every 120 s and posts gate, triage and second opinion as a comment when it answers. No wake-on-LAN, no expiry (finding 43) |
| [`rules/`](rules/) | ~110 custom rules in 12 files. `01xx` own sources, `09xx` overrides on Wazuh standard rules (load order, finding 33). Exceptions are child rules, not siblings placed in front: Wazuh tries siblings by level, not by file order (finding 44) |
| [`scripts/sync-check.sh`](scripts/sync-check.sh) | live rules, agent-group configs, CDB lists, Velociraptor artifacts and the scripts on the Pis and the manager against the repo. `check` / `diff FILE` / `pull`. Redacts secrets, flags duplicate rule IDs. Changes go to the systems first, the repo is pulled into line |
| [`scripts/daily-check.sh`](scripts/daily-check.sh) | the daily check: counts with their expected values, top rules, triage and spool status, Pi-hole blocks per hour from the FTL database, watchdog red lines. Two lines exist because a number was wrong for days (findings 36, 37) |
| [`infra/watchdog/`](infra/watchdog/) | 15 checks from a Pi outside the stack: services, backup age, NIC hang counter, alert volume. ntfy push on state change. Knows which agents may be off and which backup storage is detached |
| [`infra/fritzbox_exporter/`](infra/fritzbox_exporter/) | FRITZ!DECT 200 power metering via the fritzbox_exporter (TR-064 Homeauto). LLM host idle: 66.5 W, measured |
| [`atomic/`](atomic/) | Atomic Red Team runner for the `redcanary` VM and the coverage table above |
| [`tests/`](tests/) | 88 decoder/rule test cases (wazuh-logtest); LLM triage evaluation set, 7 cases, 14 verdicts, run against 15 local models (finding 16) |
| [`dashboards/`](dashboards/) | the Grafana dashboard shown at the top, as JSON |
| [`docs/gen-architecture.py`](docs/gen-architecture.py) | generates the architecture diagram, light and dark |

## Operation

Daily check, about a minute: NIC hang counter on the hypervisor (expected 0),
alert count without level 1, detector counts next to their expected values,
what reached triage, what is waiting in the spool, Pi-hole blocks per hour,
watchdog red lines.

Backups nightly to a second SSD, weekly to a USB disk that is detached between
runs. The watchdog alerts on backup age and knows when the USB storage is
deliberately off.

The LLM host draws 66.5 W idle, so it is off unless needed. Cases are created
in IRIS immediately; the triage follows as a comment when the host is on.

Package updates come from a local apt cache. The honeypot updates through it
without any other outbound route.

Changes are made on the systems, `sync-check.sh` pulls the repo into line.
Its first run found five agent-group configurations that had never been
versioned.

[TUNING.md](TUNING.md): 45 numbered findings, including my own mistakes.

## Not included

No installation guide. Configurations are in the repo to be read, not
installed. Secrets, API keys and the IRIS/MISP service accounts are not in
the repo, nor are the local rule overrides that contain hostnames and
addresses from outside the lab.

## License

MIT
