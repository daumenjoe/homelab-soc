# Regelübersicht

Erzeugt mit `scripts/gen-rule-table.py` – nicht von Hand pflegen.

## `0100-pihole_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110000 | 0 |  |  |  | Pi-hole DNS event |
| 110002 | 0 | 110000 |  |  | Pi-hole: external, non-allowlisted DNS event |
| 110003 | 0 | 110002 |  |  | Pi-hole: external DNS event, non-CDN |
| 110010 | 3 | 110002, 110003 |  |  | Pi-hole: domain $(dns.domain) blocked ($(dns.block_reason)) |
| 110020 | 3 | 110002, 110003 |  |  | Pi-hole: TXT query for $(dns.domain) from $(srcip) |
| 110021 | 8 | 110020 (freq) | 20× / 120 s | T1071.004, T1048.003 | Pi-hole: $(srcip) sent 20+ TXT queries in 2 min - possible DNS tunneling |
| 110022 | 7 | 110003 |  | T1048.003 | Pi-hole: oversized DNS label (40+ chars) in $(dns.domain) from $(srcip) |
| 110023 | 6 | 110003 |  |  | Pi-hole: oversized FQDN (70+ chars): $(dns.domain) |
| 110024 | 6 | 110003 |  | T1568.002 | Pi-hole: DGA-like domain $(dns.domain) from $(srcip) |
| 110030 | 2 | 110002, 110003 |  |  | Pi-hole: NXDOMAIN for $(dns.domain) |
| 110031 | 8 | 110030 (freq) | 25× / 60 s | T1568.002 | Pi-hole: 25+ NXDOMAIN replies in 60s - DGA / domain-flux activity suspected |
| 110040 | 7 | 110010 (freq) | 30× / 300 s | T1071.004 | Pi-hole: $(dns.domain) blocked 30+ times in 5 min - beaconing to blocked domain |
| 110050 | 5 | 110002, 110003 |  | T1572 | Pi-hole: $(srcip) resolving DoH endpoint $(dns.domain) - possible DNS filter bypass |
| 110060 | 4 | 110003 |  |  | Pi-hole: query to high-abuse TLD $(dns.domain) from $(srcip) |
| 110025 | 7 | 110022, 110023, 110024, 110060 |  | T1071.004 | Pi-hole: TXT query with suspicious name $(dns.domain) from $(srcip) |
| 110026 | 10 | 110025 (freq) | 10× / 120 s | T1071.004, T1048.003 | Pi-hole: $(srcip) sent 10+ TXT queries with suspicious names in 2 min - likely DNS tunneling |

## `0101-unbound_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110070 | 0 |  |  |  | Unbound resolver event |
| 110071 | 9 | 110070 |  | T1557, T1565.002 | Unbound: DNSSEC validation failure for $(dns.domain) ($(dns.qtype)) - $(dns.reason) |
| 110072 | 2 | 110070 |  |  | Unbound: SERVFAIL for $(dns.domain) |
| 110073 | 7 | 110072 (freq) | 15× / 60 s |  | Unbound: 15+ SERVFAIL in 60s - upstream resolution failing (uplink issue, hijack or DNSSEC problem) |
| 110074 | 5 | 110070 |  | T1071.004 | Unbound: large DNS response ($(dns.response_size) bytes) for $(dns.domain) $(dns.qtype) |
| 110075 | 3 | 110070 |  |  | Unbound: slow resolution ($(dns.duration)s) for $(dns.domain) |
| 110076 | 5 | 110070 |  |  | Unbound error: $(dns.message) |
| 110077 | 3 | 110070 |  |  | Unbound restarted |

## `0102-pihole_analytics_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110090 | 0 |  |  |  | pihole-analytics event |
| 110091 | 8 | 110090 |  | T1071.004, T1573 | DNS beaconing: $(pihole_analytics.client) -> $(pihole_analytics.domain) every ~$(pihole_analytics.median_interval)s ($(pihole_analytics.events) events, regularity $(pihole_analytics.regularity)) |
| 110092 | 6 | 110091 |  | T1071.004 | DNS beaconing to blocklisted domain: $(pihole_analytics.client) -> $(pihole_analytics.domain) ($(pihole_analytics.blocked_queries) blocked) |
| 110093 | 8 | 110090 |  | T1568.002 | DGA-like domain $(pihole_analytics.domain) from $(pihole_analytics.client) (score $(pihole_analytics.score), entropy $(pihole_analytics.entropy)) |
| 110094 | 7 | 110090 |  | T1568.002 | NXDOMAIN storm from $(pihole_analytics.client): $(pihole_analytics.nxdomain_unique) unique failures, ratio $(pihole_analytics.ratio) |
| 110095 | 6 | 110090 |  | T1583.001 | Newly registered domain $(pihole_analytics.registrable) queried by $(pihole_analytics.client) ($(pihole_analytics.domain)) |
| 110096 | 1 | 110090 |  |  | pihole-analytics run: $(pihole_analytics.queries_new) new queries, NRD entries $(pihole_analytics.nrd_entries) |
| 110097 | 5 | 110090 |  |  | pihole-analytics error: $(pihole_analytics.message) |
| 110098 | 4 | 110096 |  |  | pihole-analytics running without NRD list - NRD detection inactive |
| 110099 | 12 | 110090 |  | T1568.002, T1071.004, T1583.001 | Correlated DNS findings: $(pihole_analytics.client) -> $(pihole_analytics.registrable) ($(pihole_analytics.signals)) |
| 110080 | 10 | 110090 |  | T1071.004, T1048.003 | DNS tunneling suspected: $(pihole_analytics.client) -> $(pihole_analytics.registrable) ($(pihole_analytics.unique_long) unique long subdomains, $(pihole_analytics.payload_chars) chars, new-name ratio $(pihole_analytics.new_ratio)) |
