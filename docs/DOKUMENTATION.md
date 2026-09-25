# DNS Detection Engineering im Homelab
### Pi-hole · Unbound · Wazuh · pihole-analytics

Stand: 18. September 2026

---

## 1. Warum das Ganze

Ein SIEM ist nur so gut wie die Telemetrie, die es bekommt, und die Regeln, die darauf laufen. Beides selbst zu bauen – von der Datenquelle über Decoder und Regeln bis zur Auswertung jenseits der Rule Engine – ist das, was „Detection Engineering" tatsächlich bedeutet. Dieses Projekt tut genau das auf der ergiebigsten Telemetriequelle, die ein Heimnetz hergibt: DNS.

Jedes Gerät im Netz muss Namen auflösen, bevor es mit dem Internet spricht. Malware, Command-and-Control, Datenexfiltration, Phishing – fast alles hinterlässt Spuren im DNS, bevor irgendwo ein Paket mit Nutzdaten fließt. Wer den Resolver kontrolliert, sieht alles: welcher Client wann welchen Namen fragt, ob die Antwort aus dem Cache kam, ob sie kryptografisch vertrauenswürdig war, ob die Domain gestern erst registriert wurde.

Das Projekt verfolgt drei Ziele:

1. **Eine vollständige Detection-Kette selbst aufbauen** – Datenquelle anbinden, Logformat verstehen, Decoder schreiben, Regeln mit MITRE-Mapping formulieren, testen, tunen, dokumentieren.
2. **Über die Rule Engine hinausgehen.** Wazuh kann zählen („20 TXT-Anfragen in 2 Minuten"), aber es kann keine Intervall-Streuung berechnen, keine Entropie bestimmen und keine 11-Millionen-Einträge-Liste abgleichen. Dafür gibt es ein eigenes Analytics-Modul.
3. **Den Prozess sichtbar machen.** Jeder Treffer wird triagiert und mit Bewertung und Maßnahme im Tuning-Log festgehalten. Die Frage „Wie sind Sie mit False Positives umgegangen?" hat damit eine Antwort mit Datum und Zahlen.

Alles läuft zu Hause auf eigener Hardware. Es geht nicht um die Datenquelle, sondern darum, dass der Aufbau eigenhändig gemacht, getestet und verstanden ist.

---

## 2. Architektur

```
                 ┌──────────────────────────────────────────────┐
                 │  Raspberry Pi 4  (Raspberry Pi OS / Trixie)  │
                 │                                              │
 LAN-Clients ──► │  Pi-hole v6.4.3 (FTL 6.7)                    │
 Port 53         │   ├─ /var/log/pihole/pihole.log  ───────┐   │
                 │   └─ /etc/pihole/pihole-FTL.db  ──┐      │   │
                 │            │                      │      │   │
                 │            ▼ 127.0.0.1#5335       │      │   │
                 │  Unbound 1.22 (rekursiv, DNSSEC)  │      │   │
                 │   └─ /var/log/unbound/unbound.log ┼──┐   │   │
                 │                                   │  │   │   │
                 │  pihole-analytics (systemd-Timer) ◄┘  │   │   │
                 │   ├─ nrd.db  (smet.cz, täglich)       │   │   │
                 │   └─ /var/log/pihole-analytics/       │   │   │
                 │        analytics.log (JSON) ─────┐    │   │   │
                 │                                  │    │   │   │
                 │  Wazuh-Agent 4.14.7 ◄────────────┴────┴───┘   │
                 └──────────────────┬───────────────────────────┘
                                    │ 1514/tcp
                 ┌──────────────────▼───────────────────────────┐
                 │  Proxmox VM: Wazuh Manager 4.14.7            │
                 │   ├─ decoders/0100-pihole, 0101-unbound      │
                 │   ├─ rules/0100-pihole, 0101-unbound,        │
                 │   │        0102-pihole_analytics             │
                 │   ├─ lists/dns-allow (CDB)                   │
                 │   └─ Indexer + Dashboard                     │
                 └──────────────────────────────────────────────┘
```

**Datenfluss:** Client fragt Pi-hole → Pi-hole loggt Query, Antwort und Blockentscheidung → nicht gecachte Anfragen gehen an Unbound, der rekursiv auflöst und DNSSEC validiert → beide Logs liest der Wazuh-Agent zeilenweise und schickt sie an den Manager → dort zerlegen Decoder die Zeilen in Felder, Regeln bewerten sie, Frequency-Regeln korrelieren über Zeit → parallel wertet das Analytics-Modul alle 15 Minuten die FTL-Datenbank statistisch aus und liefert seine Ergebnisse als JSON auf demselben Weg ins SIEM.

Drei Sensoren, eine Kette: **Pi-hole** sieht *wer was fragt*, **Unbound** sieht *ob die Antwort vertrauenswürdig ist*, **pihole-analytics** sieht *Muster über Zeit*, die keine Einzelzeile verrät.

### Umgebung

| Komponente | Version / Hardware |
|---|---|
| Hypervisor | Proxmox, Ryzen 5 3600, 47 GB RAM |
| SIEM | Wazuh 4.14.7 Single-Node, VM 8 vCPU / 8 GB / 100 GB |
| DNS-Sensor | Raspberry Pi 4, Pi-hole Core 6.4.3 / Web 6.6 / FTL 6.7, Unbound 1.22.0 |
| Agents | Pi-hole (ID 002), Ubuntu-22.04-Laptop, Debian-11-Backup-Rechner |
| NRD-Feed | smet.cz, 30-Tage-Liste, ~11,4 Mio. Einträge |

---

## 3. Modul 1 – Pi-hole Query-Log

### Zweck
Jede DNS-Anfrage jedes Clients als Ereignis im SIEM, mit Client-IP, Domain, Abfragetyp, Antwort und Blockgrund als eigene Felder. Darauf laufen Regeln für die klassischen DNS-Missbrauchsmuster.

### Datenquelle
`/var/log/pihole/pihole.log` – das dnsmasq-Query-Log von FTL. Voraussetzung in `/etc/pihole/pihole.toml`: `dns.queryLogging = true` und `misc.privacylevel = 0`, sonst werden Domains oder Clients anonymisiert.

Zeilenformat (FTL 6.x):
```
Sep 17 21:08:30 dnsmasq[920]: query[A] cti.wazuh.com from 192.168.178.220
Sep 17 21:08:30 dnsmasq[920]: forwarded cti.wazuh.com to 127.0.0.1#5335
Sep 17 21:08:30 dnsmasq[920]: cached cti.wazuh.com.cdn.cloudflare.net is 104.21.40.220
Sep 17 21:17:45 dnsmasq[920]: gravity blocked tracker.example.net is 0.0.0.0
Sep 17 21:08:22 dnsmasq[920]: cached-stale clients.l.google.com is NODATA
```

Die Zeile hat keinen Hostnamen zwischen Zeitstempel und Prozess; Wazuhs Syslog-Predecoder nimmt daher `dnsmasq[920]:` als Hostname. Das stört nicht, weil der Decoder auf den vollen Log matcht.

### Decoder (`0100-pihole_decoders.xml`)
Ein Parent `pihole` mit Prematch `dnsmasq[\d+]: ` und ein Child pro Verb – `query`, `blocked`, `forwarded`, `reply`, `cached`, `cached-stale`, `config`. Jedes Child hat einen literalen Prematch und einen eigenen Regex; auf Alternation (`a|b`) in OSRegex wird bewusst verzichtet, weil sie nicht verlässlich ist.

Extrahierte Felder:

| Feld | Quelle |
|---|---|
| `srcip` | Client-IP aus der `query`-Zeile (einzige Zeile, die den Client enthält) |
| `dns.qtype` | A, AAAA, TXT, HTTPS, PTR … |
| `dns.domain` | abgefragter Name |
| `dns.answer` | IP, `NXDOMAIN`, `NODATA`, `<CNAME>`, `0.0.0.0` |
| `dns.block_reason` | `gravity`, `regex`, `exactly`, `denied` |
| `dns.upstream` | Ziel der Weiterleitung (`127.0.0.1#5335` = Unbound) |

### Regeln (`0100-pihole_rules.xml`, IDs 110000–110060)

Die Regeln sind in zwei Gate-Ebenen organisiert, damit Ausnahmen an genau einer Stelle gepflegt werden statt in jeder Detection einzeln. Gate 1 (110002) lässt nur externe, nicht allowgelistete Domains durch; Gate 2 (110003) lässt zusätzlich nur `query`-Zeilen ohne bekannten CDN-/Vendor-Suffix zu den Heuristiken. Wichtig: Wazuh wertet Level-0-Kindregeln **zuerst** aus und steigt nach einem Treffer nur noch in deren Kinder ab – Geschwisterregeln werden dann nicht mehr geprüft. Regeln, die auf beiden Pfaden gelten müssen (110010, 110020, 110030, 110050), hängen deshalb an beiden Gates (`if_sid 110002, 110003`). In der ersten Fassung fehlte das, vier Erkennungen waren tagelang blind; aufgedeckt haben es die Regressionstests (siehe `TUNING.md`, 2026-09-20).

```
110000  Basis: jedes Pi-hole-Event                            (Level 0)
 └─110002  extern + nicht auf der Allowlist                   ← Gate 1
     ├─110003  query-Zeile + kein CDN-/Vendor-Suffix          ← Gate 2
     │   ├─110022  Label ab 40 Zeichen                        (Level 7)
     │   ├─110023  FQDN ab 70 Zeichen                         (Level 6)
     │   ├─110024  DGA-Heuristik, nur zweiteilige Domains     (Level 6)
     │   ├─110060  Missbrauchs-TLD                            (Level 4)
     │   └─110025  eine der vier Heuristiken + TXT-Query      (Level 7)
     │       └─110026  10 davon pro Client in 2 min           (Level 10, DNS-Tunneling)
     │
     │   an beiden Gates (if_sid 110002, 110003):
     ├─110010  geblockt                                       (Level 3)
     │   └─110040  30x dieselbe Domain in 5 min               (Level 7, Blocklist-Beaconing)
     ├─110020  TXT-Query                                      (Level 3)
     │   └─110021  20 TXT pro Client in 2 min                 (Level 8, DNS-Tunneling)
     ├─110030  NXDOMAIN                                       (Level 2, nur Zählbasis)
     │   └─110031  25 in 60 s                                 (Level 8, DGA / Domain-Flux)
     └─110050  DoH-Endpunkt                                   (Level 5, Filter-Bypass)
```

MITRE-Mapping: T1071.004 (DNS C2), T1048.003 (Exfil über DNS), T1568.002 (DGA), T1572 (Protocol Tunneling / DoH-Bypass).

**Allowlist:** `etc/lists/dns-allow` ist eine CDB-Liste (exakte FQDNs, ein Eintrag pro Zeile mit Doppelpunkt). CDB kann nur exakt matchen, keine Suffixe – deshalb die Aufteilung: Einzelhosts in die Liste, Suffix-Familien (CDNs, Cloud) per Regex in Gate 110003.

**Lokales Tuning:** Suffixe, die nur im eigenen Netz relevant sind (Hersteller-Clouds, Telemetrie einzelner Dienste), stehen nicht im öffentlichen Regelwerk, sondern in `rules/0109-local_overrides.xml`. Die Datei wird alphabetisch nach `0100-pihole_rules.xml` geladen und überschreibt Gate 110003 per `overwrite="yes"` mit der erweiterten Liste; Kindregeln bleiben dabei am Gate hängen. Sie ist per `.gitignore` ausgenommen, wird von `deploy-manager.sh` und `collect.sh` aber mitgenommen. Ein ebenfalls nicht versionierter Testfall (`tests/cases/9x-local-*`) belegt, dass der Override greift.

### Verifiziert
- Blockierte Domain → 110010 im Dashboard mit `dns.block_reason: gravity`
- 42 TXT-Anfragen per `dig`-Loop vom Laptop → 110021 auf Level 8 mit korrekter `srcip` 192.168.178.201 und `previous_output` der korrelierten Zeilen

---

## 4. Modul 2 – Unbound

### Zweck
Pi-hole sieht nicht, ob eine Antwort echt ist. Unbound als rekursiver Resolver mit DNSSEC-Validierung liefert genau das: Bogus-Antworten (Spoofing, Cache Poisoning, kaputte Zonen), SERVFAIL-Häufungen (Upstream-Ausfall, Hijacking) und Antwortmetriken (Größe, Latenz). Das Query-Log von Unbound selbst wäre redundant – der Client ist dort immer Pi-hole –, deshalb wird bewusst nur `log-replies` statt `log-queries` aktiviert.

### Konfiguration
```
server:
    use-syslog: no
    logfile: "/var/log/unbound/unbound.log"
    log-time-ascii: yes
    verbosity: 1
    log-queries: no
    log-replies: yes
    log-servfail: yes
    val-log-level: 2
```
Logrotate in `/etc/logrotate.d/unbound`, täglich, 7 Generationen.

Zeilenformat:
```
Sep 17 21:46:36 unbound[11914:0] info: 127.0.0.1 dnssec-failed.org. A IN SERVFAIL 0.964779 0 46
Sep 17 21:46:36 unbound[11914:0] info: validation failure <dnssec-failed.org. A IN>: no keys have a DS with algorithm ECDSAP256SHA256 from 68.87.76.228 for key dnssec-failed.org. while building chain of trust
```
Die Reply-Zeile trägt acht Felder: Client, Name, Typ, Klasse, RCODE, Dauer, aus-Cache-Flag, Antwortgröße.

### Decoder (`0101-unbound_decoders.xml`)
Parent `unbound` (Prematch `unbound[\d+:\d+] `), Children `unbound-validation`, `unbound-reply`, `unbound-error`, `unbound-notice`, `unbound-info`. Der Client wird als `dns.client` abgelegt, nicht als `srcip` – sonst würde 127.0.0.1 alle `same_srcip`-Korrelationen verschmutzen. Domains kommen mit abschließendem Punkt, das ist im Ruleset berücksichtigt.

### Regeln (`0101-unbound_rules.xml`, IDs 110070–110077)

| ID | Level | Auslöser | MITRE |
|---|---|---|---|
| 110071 | 9 | DNSSEC-Validierungsfehler | T1557, T1565.002 |
| 110072 | 2 | SERVFAIL (einzeln, leise) | – |
| 110073 | 7 | 15 SERVFAIL in 60 s | – |
| 110074 | 5 | Antwort ≥ 1000 Bytes | T1071.004 |
| 110075 | 3 | Auflösung > 5 s (Ops-Signal) | – |
| 110076 | 5 | Unbound-Fehlermeldung | – |
| 110077 | 3 | Unbound-Neustart | – |

### Verifiziert
`dig dnssec-failed.org` (bewusst kaputte Testzone) → `validation failure` im Log → 110071 auf Level 9 im Dashboard mit `dns.reason` als Feld.

---

## 5. Modul 3 – pihole-analytics

### Zweck
Zwei Detection-Ziele sind mit Regex und Frequency-Zählern nicht sauber machbar:

- **Echtes Beaconing** – nicht „häufig", sondern *im festen Takt*. Dafür braucht es die Verteilung der Zeitabstände zwischen Anfragen.
- **Frisch registrierte Domains (NRD)** – der Abgleich gegen eine Liste mit Millionen Einträgen auf Ebene der registrierbaren Domain (eTLD+1).

Dazu kommen Entropie-basierte DGA-Bewertung und NXDOMAIN-Quoten pro Client, die als Zahlen präziser sind als Regex-Näherungen. Das Modul ist ein Python-Skript (nur Standardbibliothek, `tldextract` optional), das per systemd-Timer alle 15 Minuten die FTL-Datenbank read-only ausliest und Treffer als JSON-Zeilen schreibt. Der Wazuh-Agent liest diese Datei als `json`-Localfile; die Felder landen ohne eigenen Decoder als `data.pihole_analytics.*` im Index.

### Detections

**beaconing** – Für jedes Paar (Client, Domain) im 6-Stunden-Fenster: Zeitstempel sortieren, Ereignisse innerhalb von 2 s zusammenfassen (A/AAAA/HTTPS-Triplets zählen einmal), Abstände berechnen. Median der Abstände muss zwischen 15 s und 1 h liegen, mindestens 12 Ereignisse. Regelmäßigkeit wird zweifach gemessen: MAD/Median als robustes Jitter-Maß (≤ 0,15) und der Anteil der Abstände innerhalb ±20 % des Medians (≥ 0,8). Beides muss erfüllt sein. Enthält die Serie blockierte Anfragen, wird das mitgegeben – Beaconing zu einer Blocklist-Domain ist Level 10.

**dga** – Bewertet nicht den FQDN, sondern das Label der registrierbaren Domain (bei `abc.evil-xk3j.com` also `evil-xk3j`); dort sitzen DGAs, während CDN-Rauschen in Subdomains steckt. Vier Heuristiken – Shannon-Entropie ≥ 3,5, Vokalanteil ≤ 20 %, Ziffernanteil ≥ 30 %, Konsonantenkette ≥ 5 – plus NXDOMAIN als fünfter Indikator. Ab drei Treffern Alarm.

**nxdomain_ratio** – Pro Client im neuen Datenausschnitt: Anzahl unterschiedlicher NXDOMAIN-Namen und deren Anteil an allen Anfragen. Ab 20 Namen und 30 % Alarm. Fängt Domain-Flux, das die per-Domain-Gruppierung des Beaconing-Detektors umgeht.

**nrd** – Registrierbare Domain gegen die NRD-Datenbank. Als Kontextsignal (Level 6) gedacht, nicht als Vorfall: In einem 30-Tage-Fenster sind viele legitime neue Domains. Der Wert entsteht durch Korrelation mit `dga` oder `beaconing` vom selben Client.

**heartbeat** – Ein Ereignis pro Lauf mit Zählern: analysierte Anfragen, NRD-Einträge, Allowlist-Größe, ob `tldextract` aktiv ist, Findings, Laufzeit. Steht `nrd_entries` auf 0, meldet Regel 110098 – ein toter Feed bleibt nicht unbemerkt.

**Tunneling (seit v1.3.0):** DNS-Tunneling und -Exfiltration transportieren ihre Nutzlast im Anfragenamen – jeder Name ist neu. Pro Client und registrierbarer Domain zählt das Skript im 6-Stunden-Fenster die verschiedenen langen Subdomains (ab 20 Zeichen), deren summierte Länge und den Anteil neuer Namen an allen Anfragen. Alarm (Wazuh 110080, Level 10) erst, wenn alle drei Schwellen überschritten sind (60 Namen, 2.500 Zeichen, Anteil 0,4). Die Werte stammen aus einer 24-Stunden-Baseline des echten Verkehrs: Das auffälligste gutartige Paar lag bei 49 Namen, 1.805 Zeichen und 0,33 – Browser fragen jeden Namen als A, AAAA und HTTPS an, ein Tunnel nur einmal. Wiederholte lange Telemetrie-Labels und Werbe-Hashes bleiben damit still; bewusster Preis: sehr langsame Exfiltration weniger Kilobyte rutscht durch.

**Korrelation (seit v1.2.0):** Einzelsignale sind fast immer gutartig – das hat die Triage gezeigt. Eine frisch registrierte Domain, die zusätzlich generiert aussieht oder im festen Takt kontaktiert wird, ist dagegen ein starker Indikator. Das Skript führt deshalb pro Client und registrierbarer Domain ein Signal-Gedächtnis (7 Tage, unabhängig von den Alert-Cooldowns, die pro Domain gelten und einen zweiten Client sonst spurlos ließen). Liegt `nrd` zusammen mit `dga`, `beaconing` und/oder `tunneling` vor, entsteht ein `correlation`-Event (Wazuh 110099, Level 12); kommt später ein weiteres Signal dazu, wird erneut alarmiert.

### Rauschunterdrückung
- **Allowlist** (`/etc/pihole-analytics/allowlist.txt`): Zeilen mit führendem Punkt matchen als Suffix, sonst exakt auf FQDN oder eTLD+1. Das ist das vorgesehene Werkzeug gegen TTL-getriebene Neuauflösung von Dauerläufern.
- **Single-Label-Filter**: Namen ohne Punkt werden ignoriert – unqualifizierte Hostnamen und dnsmasq-Platzhalter wie `opcode` können das Internet nicht erreichen.
- **Cooldown pro Treffer** (Beaconing 6 h, DGA/NRD 24 h, NXDOMAIN 1 h), Zustand in `state.json`.

**Mindestdauer (seit v1.2.1):** Beaconing zählt erst, wenn das Muster mindestens eine Stunde anhält (`beacon.min_duration_seconds`). Seiten mit automatischem Werbe-Reload erzeugen sonst binnen Minuten ein Dutzend perfekt regelmäßiger „Beacons“.

### NRD-Feed
Quelle: `https://smet.cz/nrd/data/30d.txt.gz` (CC BY 4.0, Namensnennung „NRD data by smet.cz"). Der tägliche Update-Job lädt das gzip, prüft eine Mindestgröße und importiert in eine SQLite-Tabelle mit `domain` als Primärschlüssel (`WITHOUT ROWID`, also direkt der B-Tree-Index). Der Tausch erfolgt atomar. Ergebnis: 11,4 Mio. Einträge in 256 MB, Lookup pro Domain ist ein Index-Hit, der Analytics-Lauf braucht dafür keinen nennenswerten Speicher. Die erste Version hielt die Liste als Python-Set im RAM – auf dem Pi bei dieser Listengröße nicht tragbar, deshalb der Umbau.

### Betrieb und Härtung
- Läuft als User `pihole`, DB read-only geöffnet, `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`; nur State- und Log-Verzeichnis sind beschreibbar (`StateDirectory`, `LogsDirectory`).
- Timer: Analyse alle 15 min (`Persistent=true`, zufällige Verzögerung 60 s), NRD-Update täglich 04:30 mit `Nice=15` und `IOSchedulingClass=idle`, damit Pi-hole beim Import nicht ruckelt.
- Logrotate wöchentlich, 8 Generationen.
- Erster Lauf scannt 24 h zurück, danach nur neue Query-IDs.

**Schreibreihenfolge (seit v1.1.1):** Findings werden im Speicher gesammelt, am Ende in einem Rutsch geschrieben und per `fsync` gesichert – erst danach wird der State gespeichert. Ein Abbruch dazwischen führt schlimmstenfalls zu einem doppelten Alert im nächsten Lauf, nie zu einem verlorenen Alert samt Cooldown.

### Wazuh-Regeln (`0102-pihole_analytics_rules.xml`, IDs 110080, 110090–110099)

| ID | Level | Detection | MITRE |
|---|---|---|---|
| 110091 | 8 | beaconing | T1071.004, T1573 |
| 110092 | 6 | beaconing mit blockierten Anfragen | T1071.004 |
| 110093 | 8 | dga | T1568.002 |
| 110094 | 7 | nxdomain_ratio | T1568.002 |
| 110095 | 6 | nrd | T1583.001 |
| 110096 | 1 | heartbeat | – |
| 110097 | 5 | error | – |
| 110098 | 4 | heartbeat ohne NRD-Liste | – |
| 110099 | 12 | correlation: nrd + dga und/oder beaconing, gleicher Client und gleiche Domain | T1568.002, T1071.004, T1583.001 |
| 110080 | 10 | tunneling: viele verschiedene lange Subdomains, ein Client, eine Domain | T1071.004, T1048.003 |

### Verifiziert
Synthetische FTL-Datenbank mit 60-s-Beacon, drei DGA-Domains, NXDOMAIN-Sturm und einem NRD-Treffer: alle erkannt, zweiter Lauf liefert nur den Heartbeat. Produktiver Erstlauf auf dem Pi: 20.931 Anfragen in 7 Sekunden, 11.427.920 NRD-Einträge geladen, `tldextract` aktiv, 5 Findings.

---

## 6. Tests

| Ebene | Methode |
|---|---|
| Decoder | `wazuh-logtest` mit echten Logzeilen; Phase 2 muss alle Felder zeigen, Phase 3 die erwartete Rule-ID |
| Frequency-Regeln | `dig`-Loops von einem LAN-Client (TXT-Sturm, NXDOMAIN-Sturm) |
| DNSSEC | `dig dnssec-failed.org` gegen Unbound |
| Analytics | synthetische FTL-DB mit bekannten Mustern; Regression bei jeder Skriptänderung |
| Beaconing live | `for i in $(seq 1 14); do dig beacon-test.invalid @<pi>; sleep 60; done` |

Geplant für das Repo: `tests/samples.log` mit anonymisierten Echtzeilen, `tests/expected.md` (Zeile → Rule-ID) und `tests/run-logtest.sh`, damit jeder Fork mit einem Befehl prüfen kann, ob die Regeln noch greifen.

---

### Automatisierte Regressionstests

Seit dem 20.09.2026 liegt jeder Testfall als Datei in `tests/cases/`: echte Logzeilen plus die Menge der Rule-IDs, die feuern muss. `tests/run-logtest.sh` schickt jeden Fall in einer eigenen `wazuh-logtest`-Session durch das deployte Ruleset (nötig für Frequency-Regeln) und vergleicht Soll und Ist; `--record` hält den Ist-Zustand einmalig als Soll fest, `--table` erzeugt `tests/expected.md`. Zu jeder Detection gehört mindestens ein Positiv- und, wo Gates oder Tuning im Spiel sind, ein Negativtest. Der erste Lauf hat sofort einen stillen Fehler im Gate-Design gefunden – manuelle Einzeltests altern mit jeder Regeländerung, automatisierte nicht.

## 7. Tuning

Jeder Treffer wird in `TUNING.md` triagiert: Datum, Detection, Indikator, Client-Typ, Bewertung (TP / FP / benign / artefact), Maßnahme. Der erste Tag hat fünf Fälle geliefert, alle erklärbar, jeder auf eine andere Art:

| Indikator | Client | Bewertung | Maßnahme |
|---|---|---|---|
| Projektseite eines Open-Source-Clients (entropy + nxdomain) | Ubuntu-Laptop | FP – apt-SVCB-Lookup, Entropie eines langen normalen Wortes | `dga.min_score` 2 → 3 |
| `*.3gppnetwork.org` | Smartphone | benign – VoWiFi-ePDG-Discovery, `sos.`-Variante ist NXDOMAIN by design | Allowlist |
| `www.msftconnecttest.com` | Windows-Laptop | benign – Windows-Konnektivitätscheck (NCSI) | Allowlist |
| `opcode` alle 294 s, 73 Events | Fritzbox Mesh-Repeater | Artefakt – dnsmasq-Platzhalter für Nicht-Query-Pakete (Mesh-Koordination) | Single-Label-Filter im Skript |
| Telemetrie-Endpunkt eines Hardware-Herstellers, alle 301 s | Windows-Laptop | benign – Hersteller-Telemetrie | Allowlist, `beacon.min_events` 8 → 12 |

Baseline: 20.931 Anfragen, 5 Findings, 0 True Positives. Der Beaconing-Detektor hat dabei sauber funktioniert – er hat nur keinen Angreifer, sondern eine Protokollbesonderheit und einen Telemetrie-Takt gefunden. Das ist das erwartete Ergebnis in einem sauberen Netz und gleichzeitig der Beweis, dass die Erkennung greift.

---

## 8. Stolperfallen, die es zu kennen lohnt

- **Decoder-Dateien gehören nach `etc/decoders/`.** Landen sie unter `etc/rules/`, meldet der Rules-Loader „Invalid root element decoder".
- **Wazuhs XML-Parser löst Entities nicht auf.** `&lt;` im Regex wird buchstäblich gesucht. Spitze Klammern im Log mit `\.` (beliebiges Zeichen) oder `\S` abdecken.
- **OSRegex-Alternation ist nicht verlässlich.** Ein Child-Decoder pro Variante mit literalem Prematch ist robuster als `(a|b)`.
- **Level-0-Kindregeln werden zuerst geprüft – und danach nur noch deren Kinder.** Eine Level-0-Gate-Regel, die fast alles matcht, verschluckt ihre Geschwister. Regeln, die auf beiden Pfaden gelten sollen, brauchen beide Eltern (`if_sid A, B`). Ohne Regressionstest fällt das nicht auf: „nichts kommt“ sieht aus wie „alles ruhig“.
- **Level-0-Regeln taugen nicht als Zählbasis.** Wazuh merkt sich Level-0-Treffer nicht für `if_matched_sid`; eine Frequency-Regel darauf feuert nie. Basisregeln für Korrelation bekommen Level 2 – unter `log_alert_level`, also unsichtbar, aber zählbar.
- **`negate` greift nur bei vorhandenem Feld.** Fehlt das Feld im Event, matcht die Regel nicht, auch nicht negiert. Für „alles außer X“ ein Feld wählen, das jedes Event trägt (beim Docker-Listener das Image, nicht das Compose-Label).
- **Regeldateien werden über alle Verzeichnisse hinweg nach Namen sortiert geladen.** Eine Kindregel einer eingebauten Regel (z. B. Docker 87903 aus `0455-…`) muss in einer Datei mit höherer Nummer stehen, sonst „Signature ID not found“ und die Regel wird stillschweigend ignoriert.
- **CDB-Listen matchen nur exakt.** Suffix-Familien brauchen eine Regex-Gate-Regel.
- **Alerts unter `log_alert_level` (Standard 3) erscheinen nicht im Dashboard.** Level-2-Regeln existieren nur als Basis für Frequency-Korrelation.
- **Neue `<localfile>` in der `agent.conf` brauchen bis zu 10 Minuten** für den Shared-Config-Sync; `grep "Analyzing file" ossec.log` auf dem Agent zeigt, ob die Datei gelesen wird.
- **Unbound cached SERVFAIL.** Für wiederholte DNSSEC-Tests vorher `unbound-control flush <domain>`.
- **Debians `python3-tldextract` liefert den PSL-Snapshot nicht mit** und lädt lazy – der Fehler kommt beim ersten Aufruf, nicht beim Import. Das Skript probiert den Snapshot, dann einen Download in den State-Ordner, dann den eingebauten Fallback.
- **`opcode` ist keine Domain.** Pi-hole zeigt so Nicht-Query-DNS-Pakete an; Fritzbox-Mesh erzeugt sie im 5-Minuten-Takt.
- **FTL-Status 17 ist kein Block.** „Aus veraltetem Cache beantwortet“ ist eine erlaubte Anfrage; geblockt sind 1, 4–11, 15, 16 und 18. Bis v1.2.0 zählte das Skript 17 mit – aufgefallen erst, als ein vom Blocking ausgenommener Client „geblockte“ Anfragen zeigte.
- **`json.tool` versteht kein JSON-Lines.** Zeilenweise parsen.

---

## 9. Was daraus für den Lebenslauf folgt

Konkret belegbar sind damit:

- Anbindung zweier Datenquellen an Wazuh mit eigenen Decodern (12 Child-Decoder) und 35 Regeln mit MITRE-ATT&CK-Mapping
- Detection Engineering auf DNS-Telemetrie: Tunneling, DGA, NXDOMAIN-Sturm, DoH-Bypass, Beaconing, DNSSEC-Bogus
- Ein eigenes Analytics-Modul (Python, systemd, SQLite) für statistische Erkennung jenseits der Rule Engine, inklusive Threat-Intel-Anbindung (NRD-Feed) und Least-Privilege-Härtung
- Detection-as-Code: versioniertes Repo, Deploy-Skript mit Konfigurationstest und automatischem Rollback, generierte Regelübersicht
- Automatisierte Regressionstests über `wazuh-logtest` (35 Fälle, jede Alert-Regel aller drei Module ist abgedeckt, Positiv- und Negativtests). Der erste Lauf deckte einen stillen Erkennungsausfall auf: Durch einen Fehler im Regelbaum waren vier Detections samt ihrer Korrelationsregeln tagelang blind, ohne dass es im Dashboard auffiel. Ursache analysiert, behoben, per Test abgesichert. Insgesamt fanden die Tests sechs stille Fehler in drei Modulen
- Datengetriebenes False-Positive-Tuning mit Vorher-Nachher-Zahlen: eine Regel von ca. 1.900 Alerts pro Tag auf 0 gesenkt – ohne Erkennungsverlust, per Positivtest belegt; jede Maßnahme in `TUNING.md` begründet

Formulierungsvorschlag: *„Detection Engineering auf DNS-Telemetrie im Homelab (Detection-as-Code): Pi-hole und Unbound an Wazuh angebunden (eigene Decoder, 35 Regeln mit MITRE-Mapping), selbst entwickeltes Python-Analytics-Modul für Beaconing-, DGA- und NRD-Erkennung. Automatisierte Regressionstests deckten einen stillen Erkennungsausfall auf; False Positives datengetrieben reduziert (eine Regel von ca. 1.900 Alerts/Tag auf 0 ohne Erkennungsverlust)."*

Kurzfassung für enge Lebensläufe: *„DNS Detection Engineering im Homelab (Wazuh, Pi-hole, Unbound, Python): 35 eigene Regeln mit MITRE-Mapping, Regressionstests, dokumentiertes False-Positive-Tuning."*

Für das Gespräch taugt vor allem die Geschichte hinter dem Gate-Fehler: Was war das Symptom (keines – genau das war das Problem), wie wurde es gefunden (Testfall lieferte eine andere Rule-ID als erwartet), was war die Ursache (Auswertungsreihenfolge von Level-0-Kindregeln), was wurde geändert, und wie wird verhindert, dass es wieder passiert.

---

## 10. Nächste Schritte

1. **Repo-Gerüst** – README, Decoder, Rules, Lists, `agent.conf`, Analytics-Modul, `tests/`, `TUNING.md`.
2. **Korrelationsregel** – NRD + DGA oder NRD + Beaconing vom selben Client (`if_matched_group`, `same_field`), das ist die eigentliche High-Fidelity-Detection.
3. **Dashboard** – Pi-hole/Unbound-Sicht in Wazuh: Top-Clients, Blockquote, Alerts nach Rule-ID über Zeit.
4. **Honeypot** (Cowrie/OpenCanary auf dem Pi 5) – läuft nach dem Aufbau von allein und liefert reale Angreifer-Telemetrie.
5. **Netzwerksensor** (Suricata, EVE-JSON) – NIDS-Alerts im selben SIEM, Korrelation mit DNS.
6. **Velociraptor + Atomic Red Team** – Erkennung → Response → Forensik als Kette.
7. **LLM-Triage** – Alerts aus dieser Pipeline als Eingabe für lokale Vorbewertung; Trefferquote gegen manuelle Triage messen.

---

## Lizenz und Attribution

Dieses Projekt steht unter der MIT-Lizenz (siehe `LICENSE`). NRD data by [smet.cz](https://smet.cz/nrd/) (CC BY 4.0). Pi-hole, Unbound und Wazuh unter ihren jeweiligen Open-Source-Lizenzen.

- Case Management und SOAR: Wazuh-Alerts ab Level 10 per Webhook an Shuffle, dort Anreicherung (WHOIS, Threat Intel, Gerätename zur Client-IP), automatisches Anlegen eines Falls mit IOCs in DFIR-IRIS; LLM-Triage als späterer Schritt im selben Workflow