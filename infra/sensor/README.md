# Netzwerk-Sensor (Suricata)

Raspberry Pi 5, Ubuntu 24.04, Suricata 8 (OISF-PPA) mit ET Open. Zwei Schnittstellen: der USB-Adapter
(RTL8153) ist Management mit fester IP, `eth0` hängt ohne Adresse am Mirror-Port des Switches
(TL-SG108E V6: alle Ports ingress+egress auf den Pi-Port gespiegelt, Management-Port des Pi ausgenommen).
IPv6, WLAN und Bluetooth sind auf dem Pi aus; der Sensor liest mit, er spricht nicht.

**Ausgaben.** Das volle `eve.json` bleibt lokal (Flow, DNS, TLS, HTTP, mDNS – am Mirror sind das
Zehntausende Events pro Stunde, überwiegend mDNS und das Polling der Proxmox-Web-UI). Ein zweiter
EVE-Output `eve-wazuh.json` enthält nur `alert` und geht an den Wazuh-Agent (Gruppe `sensor`,
`agent/sensor/agent.conf`). Datei gehört `suricata:suricata` 640, der Agent-User ist in der Gruppe.

**HOME_NET.** `suricata-homenet.py` lauscht stündlich am Mirror auf ein Router Advertisement der
Fritzbox und trägt die aktuellen IPv6-Präfixe (global + ULA) in `HOME_NET` ein; Suricata wird nur bei
Änderung neu gestartet. Ohne das gilt jedes eigene Gerät über IPv6 als fremd – die Unbound-Rekursion
des Pi-hole sah so zunächst wie ein DNS-Bypass aus.

**Eigene Signaturen** (`local.rules`, SID 9000001–9000004, `priority:3`, damit Wazuh sie an der SID und
nicht an der Severity einordnet): DoH-Resolver per TLS-SNI, DoT auf 853, Klartext-DNS an fremde Resolver
(Pi-hole und Fritzbox ausgenommen), SNMP-Broadcast mit Community `public`. Deaktiviert über
`disable.conf`: `SURICATA Ethertype unknown` (RRCP-Frames des Switches).

**Wazuh-Regeln** `rules/0910-suricata_rules.xml` (110160–110168), Kinder der eingebauten 86601 – die
Datei muss nach `0475-suricata_rules.xml` laden. Severity 1 → Level 10 und 5× in 10 min → 12,
DoH/DoT → 8, DNS-Bypass → 7, Severity 2 → 6, SNMP-Discovery → 5, Engine-Events und ET INFO → 1/2.
Level 10/12 und die DNS-Bypässe gehen nach IRIS; `custom-iris` nimmt `src_ip` als Client und `tls.sni`
als Domain.

**Grenzen.** Der Mirror sieht nur, was durch den Switch läuft: alle verkabelten Systeme, aber vom WLAN
nur den Verkehr zu diesen Systemen. Für vollständige Sicht auf die Handys bräuchte es den
Capture-Stream der Fritzbox (geplant als Experiment) oder eine kabelgebundene zweite Box.
