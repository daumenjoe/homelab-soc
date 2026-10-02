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

## `0103-hw_metrics_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110100 | 0 |  |  |  | Hardware metrics event from $(hw.host) |
| 110101 | 1 | 110100 |  |  | hw: $(hw.host) cpu $(hw.cpu_temp_c)C, nvme $(hw.nvme.temp_c)C, load5 $(hw.load5), root $(hw.root_used_pct)% |
| 110102 | 7 | 110100 |  |  | hw: $(hw.host) CPU temperature high: $(hw.cpu_temp_c)C |
| 110103 | 10 | 110102 |  |  | hw: $(hw.host) CPU temperature critical: $(hw.cpu_temp_c)C - thermal throttling imminent |
| 110104 | 7 | 110100 |  |  | hw: $(hw.host) NVMe temperature high: $(hw.nvme.temp_c)C |
| 110105 | 10 | 110100 |  |  | hw: $(hw.host) NVMe reports $(hw.nvme.media_errors) media errors - check SMART, plan replacement |
| 110106 | 9 | 110100 |  |  | hw: $(hw.host) NVMe available spare down to $(hw.nvme.available_spare)% - replace soon |
| 110107 | 8 | 110100 |  |  | hw: $(hw.host) NVMe wear at $(hw.nvme.percentage_used)% of rated endurance |
| 110108 | 12 | 110100 |  |  | hw: $(hw.host) NVMe SMART self-assessment FAILED |
| 110109 | 7 | 110100 |  |  | hw: $(hw.host) root filesystem $(hw.root_used_pct)% full |
| 110110 | 5 | 110100 |  |  | hw: $(hw.host) sensors collection error: $(hw.sensors_error) |
| 110111 | 5 | 110100 |  |  | hw: $(hw.host) SMART collection error: $(hw.smart_error) |
| 110112 | 8 | 110100 |  |  | hw: $(hw.host) GPU temperature high: $(hw.gpu_temp_c)C ($(hw.gpu.busy_pct)% busy) |

## `0105-honeypot_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110130 | 0 |  |  |  | Honeypot event from $(node_id) |
| 110131 | 3 | 110130 |  |  | Honeypot $(node_id) started |
| 110132 | 8 | 110130 |  | T1046 | Honeypot touched: $(src_host) connected to $(node_id) port $(dst_port) |
| 110133 | 10 | 110130 |  | T1110, T1078 | Honeypot credential attempt: $(src_host) -> $(node_id) port $(dst_port) user '$(logdata.USERNAME)' |
| 110134 | 12 | 110133 (freq) | 5× / 300 s | T1110.001 | Honeypot brute force: $(src_host) made 5+ credential attempts against $(node_id) in 5 min |
| 110135 | 9 | 110130 |  | T1046 | Honeypot portscan detected from $(src_host) ($(logdata.SCAN_TYPE)) |

## `0106-fritzbox_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110140 | 0 |  |  |  | FRITZ!Box monitor event |
| 110141 | 1 | 110140 |  |  | fritz: heartbeat, $(fritz.hosts_active)/$(fritz.hosts_total) hosts active, WAN $(fritz.wan.status) |
| 110142 | 7 | 110140 |  | T1110 | fritz: failed login to the router: $(fritz.msg) |
| 110143 | 10 | 110142 (freq) | 5× / 900 s | T1110.001 | fritz: 5+ failed router logins in 15 min - brute force against the FRITZ!Box |
| 110144 | 3 | 110140 |  |  | fritz: login to the router: $(fritz.msg) |
| 110145 | 7 | 110140 |  | T1562 | fritz: router settings changed: $(fritz.msg) |
| 110146 | 10 | 110140 |  | T1090, T1133 | fritz: port forwarding $(fritz.change): $(fritz.proto)/$(fritz.ext_port) -> $(fritz.client):$(fritz.int_port) ($(fritz.desc)) |
| 110147 | 8 | 110140 |  | T1133 | fritz: port forwarding event in router log: $(fritz.msg) |
| 110148 | 6 | 110140 |  | T1200 | fritz: new device in the network: $(fritz.name) ($(fritz.mac), $(fritz.ip), $(fritz.iface)) |
| 110149 | 6 | 110140 |  | T1110 | fritz: WLAN authentication failed: $(fritz.msg) |
| 110150 | 3 | 110140 |  |  | fritz: $(fritz.category): $(fritz.msg) |
| 110151 | 5 | 110140 |  |  | fritz: external IP changed $(fritz.old) -> $(fritz.new) |
| 110152 | 5 | 110140 |  |  | fritz: $(fritz.category): $(fritz.msg) |
| 110153 | 5 | 110140 |  | T1133 | fritz: VPN event: $(fritz.msg) |
| 110154 | 5 | 110140 |  |  | fritz: system event: $(fritz.msg) |
| 110155 | 2 | 110140 |  |  | fritz: $(fritz.category): $(fritz.msg) |

## `0107-kismet_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110170 | 0 |  |  |  | Kismet WLAN sensor event |
| 110171 | 1 | 110170 |  |  | kismet: heartbeat, $(kismet.devices_known) devices known, $(kismet.new_devices) new |
| 110172 | 10 | 110170 |  | T1557 | WLAN evil twin: $(kismet.text) |
| 110173 | 10 | 110170 |  | T1499 | WLAN deauth/disassoc attack ($(kismet.header)): $(kismet.text) |
| 110174 | 8 | 110170 |  | T1200 | WLAN: new client $(kismet.mac) ($(kismet.manuf)) joined our AP $(kismet.bssid) |
| 110175 | 5 | 110170 |  |  | WLAN: $(kismet.mac) ($(kismet.manuf)) probes for our SSID '$(kismet.ssid)' without being connected |
| 110176 | 6 | 110170 |  |  | kismet alert $(kismet.header): $(kismet.text) |
| 110177 | 3 | 110170 |  |  | WLAN: new access point nearby '$(kismet.ssid)' $(kismet.mac) ch $(kismet.channel) $(kismet.signal) dBm |
| 110178 | 2 | 110170 |  |  | WLAN: new $(kismet.type) seen: $(kismet.mac) ($(kismet.manuf)) |

## `0900-docker_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110120 | 9 | 87903 |  | T1610, T1059 | Docker: unexpected container $(docker.Actor.Attributes.name) started from image $(docker.Actor.Attributes.image) - not part of the deployed compose project |
| 110121 | 0 |  |  |  | Docker: healthcheck exec (suppressed) |

## `0910-suricata_rules.xml`

| ID | Level | Eltern | Frequenz | MITRE | Beschreibung |
|---|---|---|---|---|---|
| 110160 | 10 | 86601 |  | T1071 | Suricata severity 1: $(alert.signature) [$(src_ip) -> $(dest_ip):$(dest_port)] |
| 110164 | 8 | 86601 |  | T1572, T1071.004 | DoH resolver contacted: $(src_ip) -> $(tls.sni) (DNS bypasses Pi-hole) |
| 110165 | 8 | 86601 |  | T1572, T1071.004 | DNS over TLS to external resolver: $(src_ip) -> $(dest_ip):853 (DNS bypasses Pi-hole) |
| 110166 | 7 | 86601 |  | T1071.004 | Plain DNS to external resolver: $(src_ip) -> $(dest_ip):53 (Pi-hole bypass) |
| 110161 | 6 | 86601 |  |  | Suricata severity 2: $(alert.signature) [$(src_ip) -> $(dest_ip)] |
| 110167 | 5 | 86601 |  | T1046 | SNMP broadcast discovery with community 'public' from $(src_ip) |
| 110162 | 1 | 86601 |  |  | Suricata engine event: $(alert.signature) |
| 110163 | 2 | 86601 |  |  | Suricata info: $(alert.signature) [$(src_ip)] |
| 110168 | 12 | 110160 (freq) | 5× / 600 s | T1071 | Suricata: 5+ severity-1 alerts from $(src_ip) in 10 min |
