# Tuning log

Every finding is triaged and recorded here. Verdicts: **TP** (true positive),
**FP** (heuristic fired on benign input), **benign** (correct detection, expected
behaviour), **artefact** (data-source quirk).

| Date | Detection | Indicator | Client | Verdict | Action |
|---|---|---|---|---|---|
| 2026-09-18 | dga | project site of an open-source client (entropy + nxdomain) | Ubuntu laptop | FP – apt SVCB/HTTPS lookup, entropy of a long ordinary word | `dga.min_score` 2 → 3 |
| 2026-09-18 | dga | `sos.epdg.epc.mncXXX.mccXXX.pub.3gppnetwork.org` | smartphone | benign – VoWiFi ePDG discovery, `sos.` variant returns NXDOMAIN by design | allowlist `.3gppnetwork.org` |
| 2026-09-18 | dga | `www.msftconnecttest.com` (low vowels + consonant run) | Windows laptop | benign – Windows NCSI connectivity check | allowlist `.msftconnecttest.com` |
| 2026-09-18 | beaconing | `opcode` every 294 s, 73 events, jitter 0.007 | FRITZ!Box mesh repeater | artefact – dnsmasq shows `opcode` for non-query DNS packets (mesh coordination) | script: ignore single-label names (v1.1.0) |
| 2026-09-18 | beaconing | telemetry endpoint of a hardware vendor, every 301 s, 8 events | Windows laptop | benign – vendor telemetry polling | allowlist; `beacon.min_events` 8 → 12; candidate for Pi-hole blocklist |

Baseline after first 24 h run: 20,931 queries analysed, 5 findings, 0 true positives.


---

## 2026-09-20 / 21 – Erste Regressionstests und datengetriebenes Tuning der Wazuh-Regeln

Domains sind in diesem Protokoll bewusst nur als Kategorie genannt.

### Befund 1: Gate 110003 verschluckte vier Erkennungen (stiller Fehler)

**Entdeckt durch:** ersten Lauf von `tests/run-logtest.sh` – ein Gravity-Block endete bei 110003 statt bei 110010.
**Ursache:** Wazuh wertet Level-0-Kindregeln zuerst aus und steigt danach nur noch in deren Kinder ab. Gate 110003 (Level 0, „kein CDN") fing damit fast jedes Event ab; die Geschwisterregeln 110010 (Blocked), 110020 (TXT), 110030 (NXDOMAIN) und 110050 (DoH) wurden nur noch für CDN-Domains geprüft – und mit ihnen die Frequency-Regeln 110021, 110031 und 110040.
**Auswirkung:** mehrere Tage keine Alerts dieser Regeln; im Dashboard nicht erkennbar, weil „nichts kommt" wie „alles ruhig" aussieht.
**Maßnahme:** betroffene Regeln hängen an beiden Gates (`if_sid 110002, 110003`). Zusätzlich Regex-Fehler behoben: der Router-Hostname ohne führenden Punkt passierte Gate 1.
**Beleg:** am Folgetag erstmals echte Treffer für 110050 (10), 110040 (4) und 110010 (ca. 2.350 in 17 h, Level 3, informativ).
**Lehre:** Negativ- und Positivtests pro Regel sind Pflicht; manuelle Einzeltests altern mit jeder Regeländerung.

### Befund 2: 110022 (überlanges Label) – ca. 1.900 Alerts / 24 h, 0 TP

**Analyse:** über 95 % aus drei gutartigen Quellen (Streaming-Telemetrie, Hersteller-Cloud vernetzter Geräte, Kollaborations-Software). Außerdem feuerte die Regel auf `reply`-/`forwarded`-Zeilen: mehrere Alerts pro Anfrage, ohne Client.
**Maßnahme:** Gate 110003 lässt nur noch `query`-Zeilen zu den Heuristiken; drei Suffixe ergänzt (seit 2026-09-21 in der lokalen Override-Datei statt im öffentlichen Regelwerk). Suffixe eines großen Cloud-Anbieters bewusst nicht aufgenommen (geringes Volumen, reales Missbrauchspotenzial).
**Ergebnis:** 0 Alerts in den folgenden 17 h; Testfall 06 belegt, dass ein echtes 40+-Zeichen-Label weiterhin feuert.
**Offen:** Unterscheidung „immer dasselbe lange Label" (gutartig) vs. „ständig neue" (Tunneling) gehört als Detection in pihole-analytics.

### Befund 3: TXT-Tunneling wurde von Heuristiken maskiert

**Analyse:** TXT-Queries mit verdächtigem Namen endeten bei 110022/110024 und zählten nie auf 110021 – ausgerechnet echtes Tunneling (lange, kodierte Labels) blieb für den Frequenzzähler unsichtbar.
**Maßnahme:** 110025 (TXT-Query mit verdächtigem Namen, Level 7) und 110026 (10 in 2 min, Level 10). 110021 bleibt für unauffällige TXT-Bursts. Testfälle 02 und 07 decken beide Pfade ab.

### Befund 4: 110092 (Beaconing auf geblockte Domain) – 4 Treffer + 4× 110040, 0 TP

**Triage:** Dienste-APIs auf Mobil- und TV-Geräten, automatische Suche des Betriebssystems nach verschlüsseltem DNS (DDR, RFC 9462, vom DNS-Filter absichtlich geblockt), Benachrichtigungsdienst einer Mail-App, ein Web-Tracker. Durchweg Apps, die stur gegen die Blockliste anrennen.
**Bewertung:** Level 10 war falsch gewichtet – „geblockt" heißt, die Verbindung kam nie zustande. Kritischer ist Beaconing auf nicht geblockte Domains (110091, Level 8).
**Maßnahme:** 110092 auf Level 6 gesenkt. Bewusst keine Allowlist-Einträge: die Treffer bleiben sichtbar, 110040 zeigt weiterhin, welches Gerät gegen die Blockliste läuft.

### Befund 5: 110024 (DGA-Heuristik) – 666 Alerts in 17,5 h, 0 TP

**Analyse:** ca. 60 % Videoserver einer Streaming-Plattform, Rest Werbe-Hashes, Cloud-Funktions-Adressen und deutsche Komposita (fünf Konsonanten in Folge sind im Deutschen normal). Gemeinsames Muster: der zufällig aussehende Teil war immer eine Subdomain einer seriösen Hauptdomain.
**Bewertung:** Denkfehler der Regel – DGA steckt in der registrierbaren Domain, zufällige Subdomains sind CDN-Alltag.
**Maßnahme:** 110024 feuert nur noch bei zweiteiligen Domains (`zufallsname.tld`). Kein einziger Allowlist-Eintrag nötig. Die präzisere DGA-Erkennung (Entropie auf eTLD+1) leistet pihole-analytics (110093). Testfälle 08 (positiv) und 09 (negativ).
**Ergebnis:** 674 Alerts am Tag des Fixes (666 davon vor der Änderung), **0** am Folgetag.

### Befund 6: Unbound-Modul – zwei weitere stille Fehler durch neue Testfälle (2026-09-21)

**Anlass:** Unbound war das einzige Modul ohne automatische Tests; neun Fälle ergänzt (10–18).
**Fehler 1 – 110076 (Unbound-Fehlermeldungen) feuerte nie:** Die Regel prüfte `decoded_as` auf den Namen eines Child-Decoders; Wazuh kennt an dieser Stelle nur den Eltern-Decoder. Beleg aus dem Betrieb: echte `error:`-Zeilen im Log, kein einziger Alert. **Maßnahme:** Prüfung auf den Text `error: `; das SERVFAIL-Echo (`error: SERVFAIL <…>`) bewusst ausgenommen, weil 110072 diese Ereignisse bereits zählt und sonst jeder SERVFAIL doppelt alarmieren würde.
**Fehler 2 – SERVFAIL-Sturm 110073 blind bei Timeouts:** Langsame SERVFAILs (über 5 s) endeten bei 110075 („langsame Auflösung", Level 3) statt bei 110072 (Level 2) und zählten nicht auf den Sturm-Alarm – ausgerechnet im relevanten Szenario (Upstream-Ausfall, DNS-Manipulation). **Maßnahme:** 110075 gilt nicht mehr für SERVFAIL-Antworten. Testfälle 13 (schnell) und 14 (langsam) decken beide Pfade ab.
**Muster:** dritte Maskierung derselben Klasse (eine Regel mit höherem Level „gewinnt" das Event, die Frequency-Regel dahinter verhungert). Prüfregel für künftige Regeln: Jede Basisregel einer Frequency-Korrelation braucht einen Testfall, in dem das Event zusätzlich die Bedingungen einer anderen Regel erfüllt.

### Befund 7: Vollständige Testabdeckung – NXDOMAIN-Sturm 110031 konnte nie feuern (2026-09-21)

**Anlass:** Testfälle für die zehn bis dahin ungetesteten Alert-Regeln ergänzt (22–27, 30–34); damit ist jede Alert-Regel aller drei Module abgedeckt (31 Fälle).
**Fehler:** Die Zählbasis 110030 (NXDOMAIN) hatte Level 0. Wazuh merkt sich Level-0-Treffer nicht für `if_matched_sid`, die Frequency-Regel 110031 (Level 8) war damit seit ihrer Entstehung wirkungslos. Im Unbound-Modul war derselbe Aufbau korrekt (Basis auf Level 2) – das Wissen war vorhanden, nur nicht überall angewendet.
**Maßnahme:** 110030 auf Level 2 (unter `log_alert_level`, also weiterhin unsichtbar, aber zählbar). Testfall 31 belegt den Alarm.
**Bilanz der Regressionstests nach zwei Tagen:** sechs stille Fehler in drei Modulen, keiner davon wäre im Dashboard aufgefallen – fehlende Alerts sehen aus wie Ruhe.

### Befund 8: Review der Analytics-Allowlist – Pauschalfreigabe mietbarer Cloud-Namensräume entfernt (2026-09-21)

**Analyse:** Die Allowlist enthielt Suffixe großer Cloud-Anbieter mit der Begründung „zufällig aussehende Labels". Das trifft auf namensbasierte Erkennung zu (dort bleibt die Liste, Wazuh-Gate 2). Im Analytics-Modul prüfen DGA und NRD aber die registrierbare Domain, die Einträge wirkten praktisch nur auf Beaconing – und das ist verhaltensbasiert. Ergebnis war ein blinder Fleck genau dort, wo gemietete C2-Infrastruktur typischerweise liegt.
**Maßnahme:** vier mietbare Namensräume entfernt; Namensräume, in denen nur der Betreiber selbst hostet, bleiben. Künftig Einzelhost-Einträge mit Begründung statt Suffix-Freibriefen.
**Ergebnis:** sofort ein zuvor unsichtbarer Treffer – ein IoT-Gateway, das rund um die Uhr im 31-Minuten-Takt sein Hersteller-Backend kontaktiert. Gerät identifiziert, Verhalten erwartet, als Einzelhost mit Begründung eingetragen.

### Befund 9: Beaconing – acht Treffer durch einen einzigen Browser-Tab (2026-09-21)

**Analyse:** acht Werbe-/Portal-Domains, ein Client, identischer 31-Sekunden-Takt, je 13–14 Ereignisse: eine offene Portalseite mit automatischem Werbe-Reload. `min_events` 12 bedeutete bei 30 s Takt, dass sechs Minuten Aktivität als Beaconing galten.
**Bewertung:** Schwäche der Detection, kein Allowlist-Thema – morgen wäre es ein anderes Portal. Echtes C2-Beaconing hält über Stunden an.
**Maßnahme (v1.2.1):** neuer Parameter `beacon.min_duration_seconds` (Standard 3600). Das Muster muss mindestens eine Stunde bestehen. Der IoT-Treffer aus Befund 8 (über 6 h) bleibt erkannt, die Tab-Treffer (7 min) entfallen – ohne Allowlist-Eintrag.

### Befund 10: Fehler im Blocked-Zähler – FTL-Status 17 ist kein Block; Korrektur zu Befund 4 (2026-09-21)

**Entdeckt durch:** Widerspruch in der Triage – ein Client, der vom Blocking ausgenommen ist, zeigte „blocked"-Zähler größer null. Gegenprobe direkt in der FTL-Datenbank: 400× Status 17, kein einziger echter Block.
**Ursache:** Status 17 bedeutet in Pi-hole v6 „aus veraltetem Cache beantwortet" (erlaubt). Das Skript führte ihn seit der ersten Version in der Liste der Block-Status; Status 18 (Block durch Upstream, EDE 15) fehlte dagegen.
**Auswirkung:** `blocked_queries` war überhöht; Regel 110092 („Beaconing auf geblockte Domain") feuerte auch für nicht geblockte Domains. **Korrektur zu Befund 4:** Die dort genannten Blocked-Zahlen stammten aus diesem Zähler und sind nicht belastbar; sicher geblockt war nur die DDR-Anfrage (Sonderdomain). Die Absenkung von 110092 auf Level 6 bleibt bestehen, die Begründung „Apps rennen gegen die Blockliste" war aber nur teilweise richtig.
**Maßnahme (v1.2.1):** Status 17 entfernt, Status 18 ergänzt; per Test mit nachgebauter Datenbank belegt (Status 17 → blocked 0, Status 1 und 18 → gezählt).
**Lehre:** Aufzählungswerte fremder Systeme gegen deren Dokumentation und gegen echte Daten prüfen – und Widersprüche in der Triage ernst nehmen, statt sie wegzuerklären.

### Befund 11: Tunneling-Detection mit Schwellwerten aus einer Baseline statt aus dem Bauch (2026-09-21)

**Anlass:** offener Punkt aus Befund 2 – „immer dasselbe lange Label" (gutartig) von „ständig neue" (Tunneling) unterscheiden.
**Vorgehen:** vor dem Bau eine Nur-Lese-Analyse über 24 h echten Verkehr (37.370 Queries): pro Client und Domain die Zahl verschiedener langer Subdomains, deren summierte Länge und der Anteil neuer Namen.
**Baseline:** auffälligstes gutartiges Paar 49 Namen / 1.805 Zeichen / Anteil 0,33 (Cloud-Dienste eines Arbeitsgeräts). Der Anteil 0,33 erklärt sich daraus, dass Browser jeden Namen dreifach anfragen (A, AAAA, HTTPS).
**Schwellen (v1.3.0):** 60 Namen UND 2.500 Zeichen UND Anteil 0,4 im 6-Stunden-Fenster. Per Test belegt: Tunnel-Muster erkannt; wiederholtes Telemetrie-Label, 49 bzw. 80 Namen im Browser-Muster bleiben still. Zusammen mit einer frisch registrierten Domain entsteht die Korrelation `nrd+tunneling` (110099).
**Bewusste Grenze:** sehr langsame Exfiltration weniger Kilobyte liegt unter den Schwellen.

### Befund 12: Regel-Review nach 24 h mit allen Korrekturen (2026-09-22)

**110031 (NXDOMAIN-Sturm, Level 8), 6 Treffer:** ausnahmslos `_https._tcp.<repository>`-Anfragen – seit Ubuntu 24 fragt `apt` beim Update für jedes Repository den HTTPS/SVCB-Record ab, fast keines hat einen, also NXDOMAIN, bei zehn Repos mit A+AAAA sind 25 in 60 s schnell erreicht. **Maßnahme:** Service-Record-Namen (`_dienst._tcp.` / `_udp.`) aus der Zählbasis 110030 ausgeschlossen; sie sind nie DGA-Kandidaten. Testfall 35.
**110050 (DoH-Endpunkt), 28 Treffer:** 19 davon ohne Client – `reply`-Zeilen, also Doppelzählung. **Maßnahme:** Regel nur noch auf `query`-Zeilen (Testfall 36). Die übrigen 9 verteilen sich auf drei Geräte, die einen bekannten DoH-Endpunkt auflösen. Ob danach tatsächlich DoH am Filter vorbeiläuft, kann DNS nicht sehen – das ist ein konkreter Anwendungsfall für Suricata (TLS-SNI, Port 443 zu bekannten DoH-Adressen).
**110022 (langes Label), 9 Treffer:** ein Betrugserkennungs-SDK, das viele Shopping-Apps einbetten; immer dasselbe Hash-Label. Suffix in die lokale Override-Datei.
**110091 (Beaconing), 4 Treffer, davon ein echter Fund:** Zwei Treffer waren Android-Telemetrie unter `googleapis.com` (Google-eigener Namensraum, für DGA/NRD bedeutungslos, als Suffix in die Analytics-Allowlist). Die anderen beiden kamen vom **Virtualisierungs-Host**: alle 35 Minuten der Mailserver des eigenen Providers, sieben Stunden lang. Ursache: eine Benachrichtigungs-Mail hing in der Postfix-Warteschlange, weil der Provider den Absender `root@<host>.fritz.box` ablehnt (Domain existiert nicht); Postfix versuchte es im Backoff-Takt erneut. Kein Angriff, aber ein seit Stunden defektes Benachrichtigungssystem, das ohne die Detection niemand bemerkt hätte. Behoben über eine gültige Absenderadresse in der Proxmox-Konfiguration.
**110092, 1 Treffer:** App-Telemetrie gegen die Blockliste, mit dem korrigierten Zähler jetzt echte Blocks. Level 6 passt.
**Bilanz:** 110010 stabil bei ~3.000/Tag (Level 3, informativ), 110024 bei 0, keine Regel unerwartet verstummt.

### Befund 13: NXDOMAIN-Sturm 110031 – zwei weitere gutartige Muster (2026-09-25)

**Analyse:** Sechs Treffer, zwei Muster: (1) Video-CDN-Servernamen, die serverseitig verschwinden und vom Player im Sekundentakt nachgefragt werden (24 NXDOMAIN/min pro Name); (2) Namen ohne TLD (kurze Hex-Fragmente, `local`) und eine IP-Adresse als Name, vermutlich Suchsuffix-Lookups und eine Virtualisierungs-Bridge eines Laptops.
**Bewertung:** DGA-Domains haben immer eine TLD; Namen ohne TLD und IPs-als-Name sind nie Kandidaten. Video-CDN-Retries sind CDN-Alltag.
**Maßnahme:** Zählbasis 110030 schließt zusätzlich Namen ohne TLD, IPs als Name und den Video-CDN-Suffix aus (Testfall 37). Positivtest 31 bleibt grün.
**Beaconing 110091:** zwei Treffer eines Laptops beim Video-Streaming (Telemetrie- und CDN-Endpunkt des Anbieters, 60-s-Takt über die Sitzungsdauer); als Einzelhost bzw. Suffix in die Analytics-Allowlist, beide Namensräume nicht mietbar.

### Befund 14: Docker-Listener – Healthchecks als Dauerrauschen (2026-09-25)

**Analyse:** 473 Events der Regel 87907 in einer Stunde vom MISP-Host: Docker-Healthchecks laufen als `exec` im Container (TCP-Probe auf den eigenen Port) und der Listener meldet jeden.
**Maßnahme:** Level-0-Kindregel 110121 verschluckt `exec`-Events mit typischen Healthcheck-Idiomen (`/dev/tcp/`, `curl -f`, `wget --spider`, `pg_isready`, `redis-cli ping` …). Eine echte Shell im Container (`exec_start: bash`) bleibt sichtbar (Testfälle 52/53). Muster statt Containername, damit es für alle Docker-Hosts gilt.

### Befund 16: LLM-Triage – Modellvergleich auf dem Evalset (2026-09-27)

Sieben angereicherte Alerts mit erwartetem Verdict (`tests/triage/`), je Modell zwei Läufe, gleicher Prompt (Verdict-Stufen definiert, Konfidenz 1–100, `think: false`, Temperatur 0,2, JSON-Schema).

| Modell | Treffer | Antwortzeit (warm) | Befund |
|---|---|---|---|
| gemma4:12b | 14/14 | 10–20 s | konsistent, Konfidenz angemessen, trennt „alte TI + Verhalten" von „TI-Fehltreffer" |
| qwen3:14b | 10/14 | 30–60 s | Richtung stimmt, vergibt nie `malicious` (auch nicht bei Honeypot-Brute-Force) |
| qwen3:30b-a3b (MoE) | 4/14 | 15–25 s | BENIGN 95 % bei Brute-Force, NRD+DGA und fremdem Container – hohe Konfidenz, falsches Urteil |
| Foundation-Sec-8B-Instruct Q4 / Q8 | 6/14 / 6/14 | 5–8 s / 20 s | alles `suspicious` (60–75 %), erkennt entlastende Fakten, entscheidet aber nicht; Q4 und Q8 identisch |

**Entscheidung:** gemma4:12b als Standardmodell der Triage (`llm_model` in `custom-iris.json`). **Lehren:** Modellgröße und Security-Tuning sagen wenig über Triage-Qualität; entscheidend ist, ob ein Modell Verhaltensbefunde und Reputation getrennt gewichtet. Ein Modell mit hoher Konfidenz und falschem Urteil ist schlimmer als keines. Quantisierung (Q4 vs. Q8) hatte keinen Einfluss. Einschränkungen: sieben Fälle; Prompt wurde nach Sichtung der 12B-Begründungen geschärft, alle Modelle liefen aber mit derselben Fassung.

**Nachtrag (2026-09-28), acht weitere Modelle auf demselben Evalset:**

| Modell | Treffer | stabil (Lauf 1 = Lauf 2) | Antwortzeit | Befund |
|---|---|---|---|---|
| qwen3.8:27b | 14/14 | 7/7 | 90–200 s (RAM) | qualitativ gleichauf mit gemma4:12b; braucht ≥ 24 GB VRAM für praktikable Zeiten |
| gpt-oss:20b | 12/14 | 5/7 | 15–40 s | stark, aber unbeständig: kippt bei 04 und 05 zwischen den Läufen |
| mistral-small3.2:24b | 10/14 | 5/7 | 50–95 s | zaghaft, langsam |
| deepseek-r1:14b | 10/14 | 4/7 | 40–105 s | einzige ehrlich kalibrierte Konfidenz (benign 20–30 % bei 07) |
| gpt-oss-safeguard:20b | 10/14 | 5/7 | 20–260 s | wie gpt-oss, langsamer |
| phi4:14b | 7/14 | 6/7 | 30–80 s | beständig, aber fast alles `suspicious` |
| Community-„Security"-Fine-Tunes (5) | 0–12/14 | – | – | alles `malicious 100 %`, alles `suspicious`, kein gültiges JSON, oder `benign 98 %` bei Honeypot-Brute-Force; Herkunft unklar, teils „uncensored" – ungeeignet für eine Triage-Kette |

**Bestätigung:** gemma4:12b bleibt Standard – 14/14, 7/7 stabil, als einziges der Spitzengruppe vollständig auf der 8-GB-Karte. **Lehren:** Beständigkeit zwischen Läufen ist ein eigenes Kriterium; Modellgeneration schlägt Modellgröße (qwen3 vs. qwen3.8); Community-Fine-Tunes mit Security-Label sind ohne eigenes Eval nicht einsetzbar. Eigene Vorhersage vor dem Lauf: gpt-oss richtig, Mistral und phi4 überschätzt.

15.10.206 llm auf 5800X3D / RX 7900 XT 20 GB, ROCm, Gemma 4 12B 60 t/s (Prompt 1.080 t/s), 257 W unter Last. num_ctx prüfen

### Befund 18: Docker-Healthchecks zweiter Anlauf (2026-09-29)

Regel 110121 (Befund 14) griff in der Produktion nicht: 83.000 87907-Events pro Tag vom MISP-Host, obwohl Testfall 52 grün war. Der Test enthielt nur mein eigenes Muster; die echten Healthchecks von MariaDB (`mysqladmin … status`) und Valkey (mehrzeiliges `sh -c '\n if [ …`) sahen anders aus. **Maßnahme:** Muster um `/bin/sh -c` als Merkmal, `mysqladmin`, `valkey-cli`, `curl`/`wget` ohne Optionsbindung und mehrzeilige Skripte erweitert; Testfall 52 enthält jetzt die drei echten Kommandos aus den Alerts. **Lehre:** Negativtests mit echten Produktionszeilen bauen, nicht mit vermuteten. Eine Volumenprüfung am Folgetag hätte den Fehlschlag am 26. gezeigt statt am 29.

### Befund 19: MISP-Treffer verfallen lassen (2026-09-29)

Der Dukes-Treffer (Bericht 2015) auf einer 2024 neu registrierten Domain eskalierte jeden Alert auf Critical. **Maßnahme:** Decaying Model in MISP aktiviert (NIDS-Standardmodell, 120 Tage, Schwelle 30; eigenes Modell ließ sich über die UI nicht mit Attributtypen verknüpfen), `includeDecayScore` in der Abfrage, plus Alters-Fallback über das Event-Datum (`misp_stale_days` 365). Verfallene Treffer: Tag `misp-stale`, keine Schweregradstufe. Dienstkonto für die Integration mit Read-Only-Rolle und IP-gebundenem Key statt Admin-Key.

### Befund 20: Suricata-Einführung – was am Mirror wirklich ankommt (2026-10-01)

Erste Stunden am Mirror-Port: 93 % der Events waren TLS ohne SNI, fast alles das Polling der Proxmox-Web-UI vom Laptop (per IP aufgerufen, daher kein SNI), dazu 40.000 mDNS-Events. Scheinbare DNS-Bypässe über IPv6 waren die Unbound-Rekursion des Pi-hole, weil HOME_NET keine IPv6-Präfixe kannte. **Maßnahmen:** Wazuh bekommt nur noch Alerts (zweiter EVE-Output), DoH-Erkennung als Suricata-Signatur auf den SNI statt über TLS-Events; HOME_NET per Router-Advertisement-Skript mit IPv6-Präfixen; Decoder-Rauschen (`Ethertype unknown`, RRCP vom Switch) deaktiviert. **Nebenbefund:** SNMPv1-Broadcasts mit `public` vom Pixel 9 (455 in 15 min) = Brother-Druckdienst bei der Druckersuche; Regel 110167 bleibt auf Level 5 ohne Ausnahme.

### Befund 21: Zweitmeinung uneins beim DoH-Fall; halluzinierte ATT&CK-ID (2026-10-01)

Erster produktiver DoH-Alert (Laptop → dns.google): gemma4:12b SUSPICIOUS 85 % („Ziel legitim, Verhalten umgeht den Pi-hole, Prozess auf dem Host identifizieren"), gpt-oss:20b BENIGN 95 % („dns.google ist harmlos, keine Aktion"). Gemma trifft den Zweck der Regel, gpt-oss bewertet Reputation statt Verhalten – dasselbe Muster wie im Evalset bei Fall 01. Gemma nannte dabei T1136.003 als DoH-Technik; die ID existiert, bedeutet aber „Create Account: Cloud Account". **Lehre:** `llm-disagree` ist ein nützliches Signal; Technik-IDs aus LLM-Antworten sind ungeprüft nicht verwendbar, die Regel selbst trägt die richtigen (T1572, T1071.004).

### Befund 22 (Hardware): SSD fällt nach zwei Minuten vom SATA-Bus (2026-10-02)

PNY CS900 im 2,5"-Käfig des M90q: beim Boot `link up 6.0 Gbps`, nach ~2 min `hardreset failed`, Platte weg – am USB-Adapter fehlerfrei. Verdacht Flachbandkabel (FRU 00XL211), Ersatz änderte nichts. **Ursache:** Link-Power-Management (`lpm-pol 3`, DIPM/DevSleep): die SSD wacht aus dem Schlafzustand nicht mehr auf. **Fix:** `libata.force=nolpm,noncq` in `GRUB_CMDLINE_LINUX_DEFAULT`. **Lehre:** Bei „beim Start da, unter Last/nach Ruhe weg" zuerst LPM ausschließen (ein Reboot), dann Kabel. Bekanntes Muster bei DRAM-losen Budget-SSDs an Intel-Chipsätzen.

### Befund 23 (Betrieb): Backup-Ziel blockiert Produktions-VM (2026-10-03)

Der wöchentliche Snapshot-Backup-Job auf die NFS-Freigabe des Backup-Rechners (430 MB RAM, ntfs-3g) brachte diesen in den Swap; NFS blieb stehen, QEMUs Backup-Job hielt daraufhin alle Schreibzugriffe der Wazuh-VM an (jbd2/opensearch/wazuh-db „blocked for more than 122 seconds"), die VM war über Stunden tot. Lösen nur mit `umount -f -l` des NFS-Mounts, dann `qm unlock`/`stop`/`start`. **Entscheidung:** VM-Backups nur noch lokal (SSD); der Backup-Rechner zieht die Archive samstags per rsync (`--bwlimit`, `mountpoint`-Prüfung). Backup-Rechner in die Wächter-Pings; NFS aus der Backup-Prüfung. **Lehre:** Ein Snapshot-Backup-Ziel muss zuverlässiger sein als die gesicherte VM. Erwogen: USB-Platte auf ext4 (ntfs-3g ist auf dieser Hardware der Flaschenhals).

**Nachtrag Befund 23 (2026-10-03, spät):** Auch der gedrosselte rsync-Pull (3 MB/s, dann 4 MB/s) ließ den Backup-Rechner nach etwa einer Stunde das Netz verlieren (RTL-8110SC/r8169, 32-Bit, 430 MB); kein persistentes Journal. **Endgültig:** USB-Platte direkt am Proxmox-Host (`ntfs3`, automount), als Storage `usb-backup`; lokaler rsync-Spiegel samstags 04:00 mit 84 MB/s (42 GB in 8 min). NFS vollständig abgebaut. Der alte Rechner bleibt nur Laptop-Backup-Ziel. Wächter prüft beide Storages (30 h / 192 h).

**Nachtrag Befund 23 (2026-10-03, spät):** Auch der gedrosselte rsync-Pull (3 MB/s, dann 4 MB/s) ließ den Backup-Rechner nach etwa einer Stunde das Netz verlieren (RTL-8110SC/r8169, 32-Bit, 430 MB); kein persistentes Journal. **Endgültig:** USB-Platte direkt am Proxmox-Host (`ntfs3`, automount), als Storage `usb-backup`; lokaler rsync-Spiegel samstags 04:00 mit 84 MB/s (42 GB in 8 min). NFS vollständig abgebaut. Der alte Rechner bleibt nur Laptop-Backup-Ziel. Wächter prüft beide Storages (30 h / 192 h).

### Befund 24: Entscheidungsmodell als Triage-Vorstufe (2026-10-04)

Ollama 0.35 bringt Entscheidungsmodelle (`/v1/systemone`, Jev-API): typisierte Fragen, Antwort als Wahrscheinlichkeitsverteilung. Auf dem Evalset: nimble (9B) 12/14, beide Läufe identisch, 1,7 s warm; eindeutige Fälle über 85 %, offene 65–76 %, Hersteller-Telemetrie 90 % benign mit `needs_human` 0,13; einziger Fehler der TI-Fehltreffer auf einer Google-Domain (76 % suspicious). tev1 (4B) 12/14, aber unscharf (eindeutiger Fall nur 70 %, Telemetrie als suspicious). **Entscheidung:** nimble als erste Stufe in `custom-iris` 2.9, Gemma nur bei `needs_human` ≥ 0,5 oder nicht-benignem Verdict. Produktiv: Telemetrie-Alert mit echter Anreicherung in 12 s als `dm-benign` ohne LLM-Runde, Tunneling-Alert `dm-suspicious` mit voller Runde. **Lehre:** Was ein Entscheidungsmodell gut kann (kalibrierte Einordnung in Sekunden), ersetzt nicht, was es nicht kann (Begründung, nächster Schritt); die Kombination ist besser als jedes Teil. Nebenbefund: Ohne Anreicherung (Testdomain `.example`) urteilt jedes Modell „suspicious" – die Fakten sind der Hebel, nicht das Modell.

### Befund 25: Atomic Red Team gegen die eigenen Detections (2026-10-04)

Wegwerf-VM `redcanary` (.231, Snapshot `clean`) mit Wazuh-Agent, Velociraptor-Client und Invoke-AtomicRedTeam (PowerShell 7.5 als tar.gz; Debian 13 hat libicu76, deshalb `System.Globalization.Invariant=true` in der runtimeconfig und powershell-yaml/Module per Git statt PSGallery). Erste getestete Techniken, alle erkannt:
- **T1053.003** (Cron) → Velociraptor 110183
- **T1098.004** (SSH-Key) → Velociraptor 110182 (Atomic-1 prüft nur Schreibrecht; echter Key manuell)
- **T1071.004** (DNS an fremden Resolver) → Suricata 110166, Echtzeit
- **T1110** (SSH-Brute-Force gegen den Honeypot) → 110133/110134, Mail + IRIS

**Betriebsbefund:** Velociraptors `diff()`-Quellverzeichnisse entstehen erst beim ersten Fund und erbten die Default-ACL nicht (`drwx------`), der Wazuh-Agent war ausgesperrt und verschluckte den ersten SSH-Key-Fund. Dauerhaft gelöst: `wazuh` in Velociraptors Gruppe, Datastore `g+rX` plus setgid auf die Verzeichnisse. **Lehre:** Die Tests haben zwei reale Lücken gefunden (ACL, schwacher Atomic T1098.004-1), nicht nur Haken gesetzt – genau das ist ihr Wert.

Testlauf: `atomic/run-atomic.sh`, Coverage in `atomic/atomic-coverage.md`. Regel: Scan/Lateral nur gegen Honeypot oder redcanary.

### Befund 26: journald-Gruppe fehlte – Auth-Überwachung auf allen modernen Hosts stumm (2026-10-04)

T1136.001 (neuer Benutzer) wurde nicht erkannt, obwohl die Regel existiert und `<log_format>journald</log_format>` in der Konfiguration stand. Ursache: Debian 13 / Ubuntu 24.04 schreiben Auth-Ereignisse (useradd, sudo, SSH, Log-Löschung) nur ins systemd-Journal, nicht nach `/var/log/auth.log`. Der Wazuh-Agent/-Manager darf das Journal aber nur lesen, wenn sein Benutzer in der Gruppe `systemd-journal` ist – sonst scheitert der Zugriff **still**, die Konfiguration sieht korrekt aus. Betraf alle 11 Linux-Agents plus den Manager: ein kompletter Zweig der Standardabdeckung (Authentifizierung, Benutzerverwaltung, Privilegieneskalation) war blind. **Fix:** `usermod -aG systemd-journal wazuh` auf allen Hosts, Dienst neu starten; Kontrolle über „Monitoring journal entries" im ossec.log. **Lehre:** Eine vorhandene Konfigurationszeile ist kein Beweis für eine funktionierende Erkennung. Nur der Angriffstest (Atomic Red Team) hat die stumme Kette aufgedeckt.

### Befund 27: Triage-Rückkopplung über Velociraptor-Listener (2026-10-05)

Über Nacht 399 Triage-Läufe für Regel 110181 (neuer Listening-Port), alle vom LLM-Host. Ursache: Jede Ollama-Inferenz öffnet einen kurzlebigen localhost-Port (GPU-Runner, wechselnde PID); Velociraptor meldete jeden als „neuen Listener", die Meldung löste eine Triage aus, die wieder eine Inferenz und damit einen neuen Port erzeugte – eine selbsttragende Schleife. Der LLM-PC lief dadurch die ganze Nacht unter Last. **Fix:** Im Artefakt `Homelab.Events.Baseline` die Listener-Query auf echte Dienste eingegrenzt: keine 127.0.0.1/::1, keine ephemeren Ports (≥ 32768). **Lehre:** Eine Endpoint-Detection, die Nebenwirkungen des eigenen Stacks erfasst (hier: der Triage-Engine), kann sich selbst befeuern. Backdoor-Listener binden auf erreichbare Adressen und feste Ports – genau darauf filtern, localhost-Rauschen raus.

### Befund 28: Sensor-Umzug auf Ubuntu 26.04 / Kernel 7.0 – Stolperfallen (2026-10-05)

Neuaufbau auf frischer Karte statt In-Place (In-Place scheiterte praktisch an der qemu-Emulation beim chroot-Bau und am Risiko, Suricata/Kismet während `do-release-upgrade` zu verlieren). Vier Dinge, die auf 26.04 anders sind als auf 24.04 Server:

1. **systemd-networkd beansprucht die Alfa-Karten.** Kismet bricht mit „set [device] managed true" ab. Auf 24.04 Server gab es das nicht. Fix: `/etc/systemd/network/25-alfa-unmanaged.network` mit `[Match] Name=wlx*` und `[Link] Unmanaged=yes`.
2. **Kismet-Metapaket nicht installierbar.** `apt install kismet` zieht alle Capture-Module nach, darunter `kismet-capture-rtl433-v2` → `librtlsdr2`, das im noble-Repo auf 26.04 nicht auflösbar ist. Fix: nur `kismet-core kismet-capture-linux-wifi kismet-logtools` installieren (WLAN reicht). Kismet-Repo hat kein `resolute`, noble läuft.
3. **Suricata-PPA hat `resolute`** (`oisf/suricata-stable`), also dort umstellen; Suricata 8.0.7 wie auf 24.04.
4. **/var/log/kismet fehlt** nach Paketinstallation → Kismet-FATAL beim Logöffnen; Verzeichnis anlegen. Nach Kismet-Neuinstallation ist die DB frisch → **neuer API-Key** nötig, der alte aus dem Backup gibt HTTPError im Poller.

Nicht vergessen (sonst still blind/leer): journald-Gruppe für `wazuh` (Befund 26), zweiter EVE-Output `eve-wazuh.json` in der frischen `suricata.yaml`, die systemd-Timer für `suricata-homenet` und `kismet-wazuh` (Skripte im Backup, Units nicht), ufw-Regeln (22, 2501) neu. Resultat: beide Radios produktiv (alfa24 = ACM 2,4 GHz, alfa56 = AXM 5/6 GHz, Kernel 7.0 trägt den mt7921u im Monitormodus, 6 h Soak bestanden).

### Befund 29: Ollama Keep-Alive hielt Modell 2 h warm (2026-10-05)

GPU/Lüfter liefen abends laut, obwohl keine Triage lief (0 Läufe/10 min). Ursache: `OLLAMA_KEEP_ALIVE=2h` (gesetzt für die Zweitmeinung, damit zwei Alerts kurz hintereinander nicht zweimal kalt laden) hielt gpt-oss:20b mit 14 GB geladen, die GPU trug Grundlast. Kein Fremdzugriff (ufw erlaubt nur den Manager, letzte echte Inferenz 2 h alt). Auf `30m` gesenkt: lange genug für eine Alert-Welle, der PC wird abends von allein leise.

### Befund 30 (Hardware): e1000e/i219 Hardware Unit Hang unter Last (2026-10-05)

Während eines Portscan-Tests (redcanary → Honeypot) fiel der komplette Proxmox-Host vom Netz: lokale Konsole lebte, aber kein Ping. `dmesg`: 290× „e1000e 0000:00:1f.6 nic0: Detected Hardware Unit Hang" ab Scan-Zeitpunkt, TX-Queue blockiert (`TDT <0>`, `next_to_watch.status <0>`), Link up. Das ist der bekannte TSO/Offload-Defekt der Intel-i219-NIC im M90q, nicht der Scan selbst – der war nur die Lastspitze, die ihn auslöste. `modprobe -r e1000e` holte das Netz nicht zurück, erst Reboot. **Fix:** Offloads abschalten, dauerhaft als `post-up /sbin/ethtool -K nic0 tso off gso off gro off tx off rx off sg off` plus `--set-eee nic0 eee off` am vmbr0 (EEE war enabled/inactive, der zweite bekannte i219-Auslöser). **Lehre:** Ein Angriffstest kann latente Hardware-Bugs triggern – der Befund ist echt und wichtig (der Host ist Single Point of Failure für fast alle Sensoren), auch wenn er nichts mit der Detection-Logik zu tun hat.

### Befund 31: OpenCanary überlebt Reboot nicht automatisch (2026-10-05)

Nach dem Proxmox-Reboot (NIC-Hang, Befund 30) war der Honeypot stumm:
`opencanary` inactive, nur der echte SSH-Port offen. Ein T1046-Scan sah
deshalb zunächst nur eine Berührung. Nach `systemctl enable --now opencanary`
lauschen wieder alle Köder (21/23/80/5900/6379), Scan liefert erwartungsgemäß
mehrere 110132.

**Prüfen/Fix:** `systemctl is-enabled opencanary` muss `enabled` sein.

**Lehre:** Jeder Sensor braucht einen Reboot-Test; ein Dienst, der nach
Neustart nicht hochkommt, ist eine stille Lücke – hier erst durch den
Angriffstest aufgefallen. (T1046: Honeypot-Scan wird über Berührungen erkannt,
kein dedizierter Portscan-Alert mangels iptables-Logging im unprivilegierten
LXC.)

---

### Befund 32: Velociraptor-Events erreichten das SIEM nicht – Brücke verloren (2026-10-06)

**Symptom:** Beim Volumen-Review nach dem Sensor-Umbau fiel auf, dass die
Velociraptor-Regeln 110180–110183 im aktuellen Alert-Log nicht vorkamen
(nur alerts.json geprüft, nicht die rotierten Tage – Treffer vom 04.10. wären
dort gewesen) — nicht mit
Treffer 0, sondern komplett abwesend. Die Erkennungen (neue Ports/Keys/Cron)
waren nur in der Velociraptor-GUI sichtbar.

**Diagnose (Quelle → Senke):**
- Regel-IDs 110180–110183: 0 Alerts, je.
- String-Suche "velociraptor" fand 54 Treffer → Fehlspur, waren PAM-Logins des
  velociraptor-Dienstusers (5501/5502). Lehre: auf Regel-IDs filtern, nicht auf
  frei assoziierte Strings.
- Kein `<localfile>` des Managers verweist auf Velociraptor. Es gab keinen Kanal.
- Datastore enthielt die Ergebnisse sehr wohl (inkl. Cron-Testzeile aus Runde 1,
  04.10. 14:07). Sensor arbeitete, Ergebnisse wurden nie abgeholt.

**Zweite Ursache, am 06.10. angenommen, am 10.10. zurückgenommen:** Basisregel
110180 stand auf `level="0"`; ich hatte das als "Regel wird verworfen, if_sid-
Kinder greifen nie" erklärt. Das ist falsch: 80700 (auditd, "Messages grouped")
ist selbst Level 0 und 80701ff feuern darunter (Befund 33c, live gesehen).
Level 0 heißt "nicht loggen", nicht "nicht matchen". Dass es nach der Änderung
auf Level 2 lief, lag am gleichzeitigen Manager-Neustart mit dem neuen
localfile. Level 2 bleibt (schadet nicht), die Ursache war allein die Brücke.

**Einordnung gegen Befund 25:** Dort "verschluckte" der Agent am 04.10. einen
SSH-Key-Fund wegen Datastore-ACL – es gab also am 04.10. einen localfile auf
den Datastore. Am 06.10. war keiner mehr da. Die Brücke wurde nicht "nie
gebaut", sondern **gebaut und verloren**, wahrscheinlich durch einen
agent.conf-Sync, der den lokalen Block auf .228 überschrieb (das Muster aus
Befund 34). Das ist das gefährlichere Bild: eine Konfiguration, die still
verschwindet. Deshalb lebt der Block seit 08.10. in der Gruppen-agent.conf.

**Fix:**
1. `<localfile>` (json) auf dem Velociraptor-Host (.228), liest
   `/var/lib/velociraptor/clients/*/monitoring/Homelab.Events.Baseline/*/*.json`,
   geht über den bestehenden Agent-Kanal zum Manager. Wichtig: Resultat-Baum
   `monitoring/` (nicht `monitoring_logs/` = nur Betriebsmeldungen).
2. 110180 level 0 → 2.

**Verifikation:** Test-Port 8111 auf iris → Diff → Datastore → Agent → Manager
→ Alert 110181 (L8) im alerts.json. Erster End-to-End-Durchlauf.

**Nebenbefund:** Artefakt-Beschreibung sagt "alle 5 Min", Period ist 60s
(Doku-Fix offen). Nur 7 von 9 Clients liefern Baseline-Listeners-Daten (welche
zwei fehlen, prüfen).

---

---

### Befund 33: Regeldatei-Ladereihenfolge bricht if_sid auf Standardregeln (2026-10-06)

**Symptom:** Neue auditd-Regel 110190 (Firewall-Manipulation, T1562.004) griff
live nicht, obwohl alle Felder korrekt dekodiert ankamen (per archives.json mit
testweise aktivem `logall_json` bewiesen: `audit.key=fw_tamper`, `exe`, `auid`,
`execve.a1` — alles da). logtest warnte "Signature ID 80700 not found in if_sid".

**Ursache:** Die Custom-Regeldatei hatte Präfix `0110` und lud damit *vor* der
Standard-auditd-Regeldatei `0365-auditd_rules.xml`. Die Parent-Regel 80700
("Audit: Messages grouped", level 0, in 0365) war zum Parse-Zeitpunkt von 0110
noch unbekannt → `if_sid 80700` ins Leere → Regel ignoriert.

**Fehlspuren ausgeschlossen:**
- Transport: Event kam vollständig dekodiert an (nicht das Problem).
- `decoded_as auditd` statt if_sid: löst die Warnung, aber verliert live gegen
  die grouping-Regel 80700 auf gleicher Ebene → kein Alert.

**Fix:** Regeldatei umbenannt `0110-` → `0910-defense_evasion_rules.xml`
(lädt nach 0365, 80700 ist dann bekannt).

**Verifikation (live, nicht nur logtest):** `nft list ruleset` → 110190 L7;
`nft flush ruleset` → 110191 L12 mit `a1=flush`. Zweistufige Erkennung bestätigt.

**Lehren:**
- Regeldatei-Nummerierung ist nicht nur Kosmetik — sie bestimmt, welche Parents
  via if_sid sichtbar sind. Custom-Regeln, die auf Standard-Regeln ankern,
  brauchen eine Nummer > der Standard-Datei.
- logtest ≠ Live-Daemon. logtest lädt in anderer Reihenfolge; "not found"-
  Warnungen am Live-Verhalten gegenprüfen.
- Level-0-Regeln erscheinen nie in alerts.json (nur als Parent nutzbar). Für
  Transport-Tests `logall_json` nutzen (danach WIEDER AUS — Platte).

#### 33a: Stillregel 110189 für Dienst-Aufrufe (2026-10-08)

**Symptom:** 12 x 110190 (L7) in der ersten Nacht, alle `auid=4294967295`
(unset, kein Login), alle nur `nft list`, 10 davon von derselben ppid. Ein
Dienst (Velociraptor-Client / nftables-Poll) liest periodisch den Ruleset.

**Fix:** Regel 110189 (level 0) **vor** 110190, haengt direkt an 80700:
`auid=^4294967295$` UND `execve.a1=^list$` -> still. Alles andere laeuft
weiter: interaktives `list` (hat auid) -> 110190 L7; `flush`/`delete` von wem
auch immer, auch ohne Login -> 110191 L12.

**Verifikation:** `systemd-run nft list ruleset` (auid unset) -> kein Alert.
Interaktives `sudo nft list ruleset` (auid 1000) -> 110190 L7. Beide live.

**Lehre:** Wazuh nimmt das erste passende Kind einer Parent-Regel in
Dateireihenfolge. Eine Stillregel muss *vor* der Basisregel stehen und an
derselben Parent haengen, nicht an der Basisregel selbst.

---

#### 33b: Zweiter Fall Ladereihenfolge – AppArmor/Discord (2026-10-09)

Stillregel 110199 fuer 52002 (Discord-Snap, ~150 DENIED/2 Tage durch ptrace
und /proc/PID/cmdline, Spielaktivitaets-Erkennung, von der Sandbox korrekt
geblockt) griff in 0109-local_overrides.xml nicht: 0109 laedt vor
0315-apparmor_rules.xml, 52002 ist beim Parsen unbekannt. Verschoben nach
0930-apparmor_overrides.xml.

**Regel daraus:** 0109 ist fuer Overrides EIGENER Regeln (110xxx, laden in
0100–0108). Overrides auf Wazuh-STANDARDregeln (5xxx, 52xxx, 80xxx) brauchen
eine 09xx-Datei. Standard-AppArmor-Decoder extrahiert nur status/extra_data,
daher Regex gegen die Rohzeile; Feldreihenfolge dort ist nicht fix
(operation= steht bei ptrace vor profile=), daher zwei Lookaheads.

---

#### 33c: Weg B – Homelab.Events.FirewallState, Zustandsüberwachung (2026-10-09)

**Ziel:** auditd (Weg A, 110190ff) sieht den *Aufruf* von nft/iptables. Es
sieht nicht: Netlink direkt (pyroute2, google/nftables), ein kopiertes Binary
unter anderem Namen, und es läuft nur, wo auditd installiert ist (redcanary).
Weg B überwacht den *Zustand* auf allen 9 Velociraptor-Clients.

**Bestandsaufnahme vorab:** Gäste sind nicht nackt. iris/misp ~100 Zeilen
(Docker via iptables-nft), llm/sensor ~320 (ufw), grafana/relay/wazuh leer.
Alle über die iptables-Kompatibilitätsschicht ("table ip filter is managed by
iptables-nft"). Folge: Chain-Namen sind stabile Signaturen (ufw-*, DOCKER-*).

**Maß:** eine Zeile je table/chain, Key = "table/chain", diff() meldet added
UND removed. Nicht Regel-Hash: Docker ändert bei jedem Container-Start Regeln
in bestehenden Chains (Rauschen), aber keine Chains. ufw disable / nft flush /
iptables -X entfernen Chains (Signal). Regelzahl je Chain als Zusatzfeld.

**VQL, an der Engine verifiziert (llm, Sollwerte aus Python):**
- `nft -j list ruleset` liefert JSON, kein Text-Parsing.
- foreach(row=<array of dicts>) legt die Dict-Schlüssel direkt in den Scope,
  kein _value. Jedes Objekt hat genau einen Schlüssel; direkter Zugriff auf
  fehlende Schlüssel = Fehler je Zeile. Lösung: get(field="chain").
- Aliase chain/rule verdecken Plugin-Namen, der Artefakt-Linter lehnt sie ab
  (symbol_mask_warn). ChainObj/RuleObj.
- Regelzahl je Chain: parametrisierte LET-Funktion und korrelierte Subquery
  sahen den äußeren Key NICHT (Rules=0 überall). Funktioniert: GROUP BY in
  ein Dict (to_dict), Lookup per get(item=, field=, default=0).
- LETs auf Source-Ebene müssen "=" sein; "<=" würde beim Artefakt-Start
  einfrieren. Preis: 3x execve je Tick. Kleinkram: LETs in die innere Query.

**Wazuh:** 110184 (L10, jede Chain-Änderung, pcre2 für ^(added|removed)$ —
OSRegex kennt keine Gruppen, Befund: CRITICAL beim Laden), 110186 (L10, nur
removed), 110185 (L12, frequency 5/120s auf 110186, same_field Host).
Erste Fassung hatte <field Diff=removed> IN der Frequenzregel: ein <field>
in einer if_matched_sid-Regel prüft nur das AKTUELLE Event, nicht die
gezählten; das letzte Event im Batch war ein "added" → nie gezündet.
Zwischenregel 110186 löst das.

**Verifikation (ufw disable auf llm, 130 s, ufw enable):** 22 x 110186
removed, 27 x 110184 added, 1 x 110185 L12 "firewall torn down on llm".
Erster Lauf mit 75 s: beide Übergänge im selben Tick, _ts identisch; 130 s
= zwei Ticks, Übergänge getrennt. Für Tests immer > 2 x Period.

**Betrieb:** vierter localfile-Block in servers/agent.conf
(.../Homelab.Events.FirewallState/Chains/*.json). Ein neuer localfile in
einer Gruppen-agent.conf wird gesynct, aber erst nach **Agent-Neustart**
aktiv ("Analyzing file" im Log). Vor einem Test prüfen (Nachtrag Befund 34).

**T1562.004 damit doppelt abgedeckt:** 110191 (Aufruf, auid, Argument) +
110185 (Zustand, alle Hosts). Feuert nur B ohne A → auditd umgangen.

---

### Befund 34: Doppeltes Wildcard im Velociraptor-localfile – Dateien doppelt registriert (2026-10-08)

**Symptom:** Tag 2 nach dem Brückenbau (Befund 32) kam ein echtes Baseline-Event
(llm öffnet Port 11434 nach Ollama-Neustart) nicht als Alert an, obwohl die
Datastore-Datei existierte und der Agent sie als "New file that matches the
pattern" erkannte. Direkt danach im Agent-Log: `Log file ... is duplicated`,
32 Warnungen pro Agent-Neustart.

**Ursache:** Das Muster `clients/*/monitoring/Homelab.Events.Baseline/*/*.json`
hat zwei Wildcard-Verzeichnisse. Wazuh expandiert das beim Start einmal und
registriert dieselbe Datei danach ein zweites Mal ueber das Pattern. Die
zweite Registrierung wird als Duplikat verworfen; beim Tagesrollover (neue
`<datum>.json`) kann die erste Zuordnung verfallen und die zweite nie lesen.
Das Event von 08:41 Uhr ging so verloren.

**Zweite Ursache (Betrieb):** Der localfile-Block lag lokal in der ossec.conf
des Agents. In diesem Setup ist die Gruppen-agent.conf die Quelle der Wahrheit;
lokale Aenderungen werden beim naechsten Sync ueberschrieben.

**Fix:**
1. Ein localfile-Block **pro Quelle** (Listeners, AuthorizedKeys, Cron), je nur
   ein Wildcard-Verzeichnis plus `*.json`. Neue Quelle = neuer Block, explizit.
2. Blocks in die Agent-Gruppe `velociraptor` (`<agent_config name="velociraptor">`)
   statt lokal. Lokaler Block entfernt. Host haengt in `servers` + `velociraptor`.

**Verifikation:** Nach Restart 0 duplicated-Warnungen (vorher 32). Frischer
Testport 8112 auf llm -> 110181 im alerts.json. Port geschlossen.

**Lehre:** Wazuh liest eine neu registrierte Datei ab Dateiende. Ein Event, das
vor der Registrierung geschrieben wurde, wird nicht nachgelesen. Bruecken-Tests
brauchen immer einen *frischen* Diff, nie einen schon vorhandenen.

---

---

### Befund 35: Ein Smart-TV erzeugt 70 % des SIEM-Tagesvolumens (2026-10-09)

**Symptom:** Tageszahl drei Tage in Folge bei 4000–4800 statt ~1500. Top-8 nach
Regel: 3323 von 4794 Alerts sind Regel 110010 (Pi-hole gravity block), die
Domains alle Telemetrie/Werbung (androidtvchannels, *.cws.conviva.com mit
40-stelligem Hex-Praefix als Session-ID, gs-loc.apple.com, braze, instagram).
Quelle: der eine Smart-TV im Haus (Philips 50PUS7354, Android TV, .29).

**Histogramm nach Stunde:** Blocks rund um die Uhr, nachts 1–4/min, tagsueber
bis 13/min, Spitzen 12 und 15 Uhr. Der Fernseher laeuft ~10 Min/Tag, ist aber
nie aus: Netzwerk-Standby ("Mit Chromecast einschalten" + WoWLAN) haelt den
Android-Stack wach, die App-SDKs wiederholen geblockte Anfragen ohne Backoff.

**Recherche Blocking-Mode:** Pi-hole-Doku: NULL (0.0.0.0, aktiv) ist der Modus
mit den wenigsten Retries; NXDOMAIN fuehrt laut Doku zu *mehr* Aufloesungs-
versuchen, IP-Modus zu HTTPS-Timeouts. Kein Hebel ueber den Modus.

**Fix, Regel-Seite:**
- 110010 Level 3 -> 1. Bleibt dekodiert und im Index (Grafana-Drilldown "Top
  geblockte Domains" funktioniert weiter), faellt aus Tageszahl und Dashboard.
- Neue 110061 (L5, frequency 30, timeframe 600, same_field dns.domain): eine
  geblockte Domain 30+ mal in 10 Min = Retry-Loop als EIN Event. Erwartung
  2–5/Tag statt 3300 Einzelzeilen.

**Fix, Geraete-Seite:** Einstellungen -> Kabellos und Netzwerke -> Kabel oder
WLAN -> "Mit Chromecast einschalten" AUS, "Mit WLAN einschalten (WoWLAN)" AUS.
Nebenwirkung: Casten weckt den TV nicht mehr. Kontrolle am Folgetag per
Stunden-Histogramm (Nachtbalken 0–6 Uhr muessen verschwinden).

**Einschraenkung:** dnsmasq-Block-Zeilen (`gravity blocked <domain> is 0.0.0.0`)
tragen keine Client-IP; die steht nur in der getrennten query-Zeile. Deshalb
Frequenz nur nach Domain. Client-Zuordnung ist Aufgabe von pihole-analytics
(FTL-DB hat Client + Domain in einer Zeile). Ausbau: Pruefung "Client x
geblockte Domain, Top-N/Tag".

**Lehre:** Das SIEM hat hier kein Sicherheitsereignis gefunden, sondern ein
Geraeteverhalten sichtbar gemacht, das ohne die Zahlen unbemerkt geblieben
waere. Ein einzelnes Consumer-Geraet kann das Dashboard dominieren; die Tages-
zahl ist nur dann eine Sicherheitskennzahl, wenn Level-1-Rauschen draussen ist.

---

**Korrektur (2026-10-10):** 110010 auf Level 1 liegt UNTER `log_alert_level`
(3). Einzelne Blocks landen damit weder im alerts.json noch im Indexer; der
Grafana-Drilldown "Top geblockte Domains" funktioniert NICHT mehr. Bewusst so
gelassen (Option C): ein einzelner geblockter Query ist keine SIEM-Information,
die Statistik fuehrt Pi-hole/FTL selbst. Im SIEM bleiben die Muster: 110061
(Retry-Loop je Domain) und 110086 (Hammering mit Client aus der FTL-DB).
Histogramme ab jetzt direkt auf der FTL-DB, nicht auf alerts.json.

**Geraeteseite bestaetigt (2026-10-10):** Nach Abschalten von "Mit Chromecast
einschalten" und WoWLAN keine Blocks mehr zwischen 0 und 6 Uhr. Der TV ist
aus, wenn er aus ist. Tagsueber bei Nutzung 2–4 x 110061 je Sitzung, das ist
das neue Normalbild.

### Befund 36: Watchdog-Backup-Check seit dem Umbau auf SSD/USB rot (2026-10-10)

**Symptom:** `BAD pve:backups local-backup none (>30h), usb-backup none (>192h)`
seit dem Umzug der Backups von der flepo auf lokale SSD + USB (Befund 23).
`pvesm status` zeigt beide Storages aktiv, `pvesh get .../content` als root
liefert je 54 Einträge. Die API antwortet dem Watchdog-Token mit HTTP 200 und
`{"data":[]}`. Die Push-Nachricht kam, wurde erkannt, aber nicht nachgezogen.

**Ursache, zwei Schichten:**

1. Der API-Token `watchdog@pve!monitor` war mit Privilege Separation angelegt
   (`privsep 1`). Ein solcher Token erbt die ACL seines Users *nicht*, sondern
   hat nur, was ihm selbst zugewiesen wurde: nichts. `pveum acl list` zeigte
   nur den User-Eintrag `/ PVEAuditor user watchdog@pve`, keinen Token-Eintrag.
   Behoben durch Neuanlage mit `--privsep 0` (der Token stand ohnehin im Chat,
   also rotiert).
2. Danach immer noch leer. Der Content-Handler
   (`PVE::API2::Storage::Content::index`) prüft jeden Eintrag einzeln mit
   `check_volume_access()` und lässt stillschweigend weg, was durchfällt. Für
   Backups verlangt diese Prüfung `Datastore.AllocateSpace` auf dem Storage
   **und** `VM.Backup` auf `/vms/<vmid>`. PVEAuditor hat keins von beiden;
   `Datastore.Audit` reicht nur für den Storage-Status und für ISOs/Templates.
   Daher: Status sichtbar, Liste leer, kein 403. Ein Patch, der die Prüfung
   aus dem Listing entfernt (pve-devel, Juli 2025, Bug #5492, Begründung
   wörtlich "monitor backup health"), ist in PVE 9 nicht enthalten.

**Fix:** eigene Rolle, eng gescoped, PVEAuditor auf `/` bleibt:

```
pveum role add WatchdogBackup -privs 'Datastore.Audit,Datastore.AllocateSpace,VM.Audit,VM.Backup'
pveum acl modify /storage/local-backup -user watchdog@pve -role WatchdogBackup
pveum acl modify /storage/usb-backup  -user watchdog@pve -role WatchdogBackup
pveum acl modify /vms                 -user watchdog@pve -role WatchdogBackup
```

Bewusst in Kauf genommen: `VM.Backup` ist nicht rein lesend (Backup anstoßen,
wiederherstellen). Rein lesende Alternative wäre die Auswertung der
vzdump-Tasks unter `/nodes/pve/tasks` statt der Content-Liste; Umbau des
Checks, nicht nur der Rechte. Notiert, nicht gebaut.

**Diagnoseweg, der funktioniert hat:** Token-Rechte aus Sicht der API
(`/access/permissions?path=…`) und aus Sicht von `pveum user token
permissions` vergleichen; `pveproxy/access.log` lesen, um Host und Antwortgröße
zu bestätigen (`200 11` = leere Liste); erst dann den Handler-Code nachlesen.
Das hat zwei falsche Vermutungen (falsche Storage-Konfig, falscher Host) in
je einem Schritt erledigt.

**Nebenbefund:** `BAD wazuh:agents 13/14 active, down: redcanary`. Die
Atomic-VM ist absichtlich nur während der Tests an. Ein Agent, der planmäßig
aus ist, darf den Check nicht dauerhaft rot färben, sonst wird der echte
Ausfall überlesen. Neu: `optional_agents` in `/etc/watchdog.json`; Ausgabe
`OK wazuh:agents 13/14 active, off (optional): redcanary`. Preis: fällt
redcanary *während* eines Laufs aus, meldet der Watchdog das nicht.

**Lehren:**
- Nach jedem Umbau am überwachten System den Wächter einmal von Hand laufen
  lassen und jede Zeile lesen, nicht nur auf den Push warten.
- Ein BAD, das dauerhaft bleibt, ist ein Check, der etwas Falsches prüft,
  nicht ein Zustand, an den man sich gewöhnt. Zwei Checks waren seit Tagen
  rot; einer davon war echt.
- PVE antwortet bei fehlenden Rechten auf Listen-Endpunkten mit 200 und
  leerer Liste, nicht mit 403. Ein Monitoring-Check gegen solche Endpunkte
  muss "leer" als Fehler behandeln, nicht als "keine Backups": das tut der
  Watchdog mit `none (>30h)` zum Glück bereits.
  
  watchdog: fix pve:backups after backup move, optional agents, sync-check for Pis
- PVE token recreated without privsep; custom role WatchdogBackup
  (content listing filters per volume, needs AllocateSpace + VM.Backup)
- optional_agents: redcanary no longer counts as down
- sync-check.sh: PI_FILES with redacted watchdog config
- TUNING: finding 36
---

### Befund 37: Rootcheck meldet Rust-Coreutils als Trojaner, 236 Level-7-Alerts am Tag (2026-10-11)

**Symptom:** Tagescheck zeigt 715 Alerts ohne L1 am Vormittag, Top-5 zum ersten
Mal gelesen: 236 x Regel 510 "Host-based anomaly detection event (rootcheck)",
114 x 550 "Integrity checksum changed". Zusammen die Hälfte des Tagesstands.

**510:** `Trojaned version of file '/usr/bin/ls' detected. Signature used:
'bash|^/bin/sh|dev/[^clu]|...' (Generic)` — zehn Coreutils-Binaries je Host,
sechs Hosts. Nicht neu: gestern dieselben Zahlen (98 bzw. 40 je Host = zwei
Rootcheck-Läufe à 49 bzw. 20 Dateien). Ursache: `/usr/bin/ls ->
../lib/cargo/bin/coreutils/ls`, Paket `coreutils-from-uutils`. Die
Rust-Coreutils der neuen Ubuntu-Version sind 2-MB-Binaries voller Strings
wie `/bin/sh` und `bash`; Rootchecks `check_trojans` greppt genau danach, mit
Signaturen aus der Zeit, als Rootkits so gebaut wurden. Gegen diese Binaries
ist die Prüfung ein Zufallsgenerator.

**Fix:** nicht Regel 510 absenken (die trägt auch versteckte Ports, Dateien in
/dev, Prozess-Anomalien), sondern die eine Prüfung aus:
`<rootcheck><check_trojans>no</check_trojans></rootcheck>` in der
`default`-Gruppen-agent.conf (alle Agenten sind Mitglied) und, weil agent.conf
für den Manager selbst nicht gilt, in dessen ossec.conf. remoted warnt danach
"Multigroup ... was modified from outside, so it was regenerated" — harmlos.
Erwartung: 510 morgen nahe 0; was bleibt, ist lesenswert.

**550 auf pve:** `/etc/pve/priv/authkey.key`, `authkey.pub*` rotiert PVE
täglich (Ticket-Signaturschlüssel); `qemu-server/*.conf` und `lxc/*.conf`
ändert vzdump beim Nachtbackup (`lock: backup` rein und raus); `.vmlist`,
`.version` sind pmxcfs-intern. Ein Backup-Lauf = ein Dutzend Level-7-FIM-Alerts,
jede Nacht, seit dem Umbau auf lokale Backups (Befund 23). Bewusst nicht
getuned: ohne `report_changes` ist eine vzdump-Lock-Zeile nicht von einer
echten Konfig-Änderung zu unterscheiden, und VM-Konfig-Änderungen will ich
sehen. Preis bekannt, steht hier.

**Nebenbefund, README war falsch:** "one case per alert of level >= 7" stimmt
nicht. Die IRIS-Integration hat einen Gruppenfilter
(`pihole,pihole_analytics,unbound,honeypot,fritzbox,docker_unexpected,
suricata,kismet,hw_metrics,velociraptor`); Wazuhs Standardgruppen (rootcheck,
syscheck, pam, apparmor) bleiben im SIEM. Deshalb haben die 236 Rootcheck-
Fehlalarme die Triage nie erreicht (Integrations-Log: 0 x 510). Richtige
Entscheidung, falsch dokumentiert; README korrigiert.

**Lehre:** Der Tagescheck zählte Summen. Eine Summe von 715 sagt nichts, wenn
die Hälfte davon seit Tagen dieselben zwei Regeln sind. Neue Zeile im
Tagescheck: Top-5-Regeln ab Level 2.

---

### Befund 38: Zwei Regeln, ein Fernseher — Befund 35 war nur halb fertig (2026-10-11)

**Symptom:** Integrations-Log, letzte drei Zeilen: `rule 110040 -> IRIS alert
845/846/847 (dm-suspicious, llm-benign, llm-disagree)` im Fünf-Minuten-Takt um
17:30. Domain: `androidtvchannels-pa.googleapis.com`. 18 IRIS-Fälle heute, 101
seit Bestehen des Logs, alle derselbe Fernseher, alle vom LLM als harmlos
eingestuft, zwei Drittel mit Widerspruch des zweiten Modells.

**Ursache:** 110040 (Level 7, "blocked 30+ times in 5 min — beaconing",
if_matched_sid 110010, same_field dns.domain) gab es schon, bevor Befund 35 die
110061 (Level 5, 30 in 10 min, "Retry-Loop") gebaut hat. Beide messen dasselbe.
Befund 35 hat die Level-1-Flut und die Push-Nachrichten gestoppt; die *teure*
Variante derselben Quelle lief weiter: Level 7, Gate-Modell, Triage-LLM,
Zweitmeinung, IRIS-Fall. Zehn davon kosten mehr Rechenzeit als die 3.300
Level-1-Alerts zusammen. Im Tagescheck unsichtbar, weil der die Summe zählt und
nicht fragt, wer die Triage beschäftigt.

**Unterschied zwischen Retry-Loop und Beaconing:** keiner in der Mechanik, nur
in der Domain. Der dnsmasq-Blockeintrag trägt keinen Client (Befund 35), also
bleibt die Domain das einzige Unterscheidungsmerkmal. Dafür gibt es CDB-Listen.

**Fix:**
- `/var/ossec/etc/lists/dns-telemetry` (Key:Kommentar), Eintrag
  `androidtvchannels-pa.googleapis.com:philips-tv`; `<list>` in ossec.conf;
  analysisd kompiliert die `.cdb` beim Start selbst.
- 110061: `<list field="dns.domain" lookup="match_key">` — bekannte
  Telemetrie, Level 5, kein IRIS.
- 110040: `<list field="dns.domain" lookup="not_match_key">` — unbekannte
  Domain, Level 7, Triage.
- Disjunkt: ein Event trifft genau eine der beiden. `<list>` in einer
  Frequenzregel prüft wie `<field>` nur das aktuelle Event (Befund 33), hier
  unschädlich, weil `same_field dns.domain` garantiert, dass alle gezählten
  Events dieselbe Domain haben.

**Verifikation (wazuh-logtest, 31 x dieselbe Blockzeile):** TV-Domain → 30 x
110010, 1 x 110061 L5, kein 110040. `c2.evil-example.net` → 30 x 110010,
1 x 110040 L7 mit MITRE T1071.004, kein 110061. Live-Gegenprüfung über den
Tagescheck am Folgetag.

**Offen:** Die Liste hat einen Eintrag. Jede weitere Telemetrie-Domain, die
einen Retry-Loop fährt, produziert erst einmal IRIS-Fälle, bis sie eingetragen
ist. Das ist gewollt: Ein unbekannter Loop *soll* einmal durch die Triage, und
"llm-benign" plus Listeneintrag ist dann der Abschluss. Die Analytics-Allowlist
auf dem Pi und diese Liste sind zwei getrennte Dinge mit ähnlichem Inhalt;
zusammenführen wäre ein Umbau, notiert.

**Tagescheck, neue Zeilen:** Top-5-Regeln ab Level 2 (Befund 37), Top-3-Regeln
im Integrations-Log *für heute* (das Log zählt seit Bestehen, 101 ist keine
Tageszahl), Pi-hole-Blocks je Stunde aus der FTL-DB statt aus alerts.json
(seit Option C in Befund 35 kommt 110010 dort nicht mehr an; die alte Zeile
war seit gestern leer und hätte es für immer bleiben können).

**sync-check.sh** kennt jetzt `lists/` (Quelldateien, nicht die .cdb; Wazuhs
eigene `audit-keys` und `security-eventchannel` ausgenommen).

### Nachtrag zu Befund 37: zweite 510-Quelle, LXC (2026-10-12)

Nach `check_trojans no` sind die Trojaner-Meldungen weg (wazuh, iris: beide
uutils). Übrig: 49 x 510 je Rootcheck-Lauf auf jedem **LXC-Container** (canary,
grafana, relay, velociraptor): `File '/dev/.lxc/proc/<x>' present on /dev.
Possible hidden file.` LXC spiegelt /proc des Containers nach /dev/.lxc/,
Rootcheck hält jede Datei dort für versteckt. Fix in der default-agent.conf:
`<ignore>/dev/.lxc</ignore>` im rootcheck-Block, nicht `check_dev no`: echte
Dateien in /dev sollen weiter auffallen. Die ursprüngliche Annahme "alle 510
sind uutils" war von der Wazuh-VM auf alle Hosts übertragen; die Frage "haben
wir auf grafana überhaupt uutils?" hat das korrigiert (`dpkg -S /usr/bin/ls`
→ coreutils).

---

### Befund 39: Velociraptor-Brücke verliert das erste Event des Tages (2026-10-11/12)

**Symptom:** `ufw disable; sleep 130; ufw enable` auf llm: Datastore hat 27 x
removed und 27 x added, Wazuh nur die 27 added. Kein 110186, kein 110185. Der
Alarm "firewall torn down" (Level 12) fehlte, nur das harmlose Wiedereinschalten
kam an.

**Ursache:** Velociraptor schreibt Event-Ergebnisse je Client, Artefakt, Quelle
und **Tag** in eine Datei (`.../monitoring/<Artefakt>/<Quelle>/<YYYY-MM-DD>.json`,
Tagesgrenze 00:00 UTC). Der Wazuh-Logcollector auf dem Velociraptor-Host liest
diese Dateien per Wildcard. Eine Datei, die erst zur Laufzeit entsteht, wird
beim Entdecken (`logcollector.vcheck_files`, Standard 64 s) **vom Ende** gelesen.
Alles, was bis dahin drinsteht, ist weg: das Event, das die Datei angelegt hat,
inklusive aller Zeilen desselben Vorgangs. Dreimal reproduziert (llm, wazuh,
grafana), auch mit `only-future-events no` in allen vier localfile-Blöcken
(`merged.mg` geprüft, Agent neu gestartet). Die Option hilft beim
Agent-Neustart (liest ab gemerkter Position), nicht bei neu entdeckten Dateien.

**Warum das schwer wiegt:** Auf einem ruhigen System meldet jede Quelle an den
meisten Tagen nichts. Fast jedes echte Event ist damit das erste seines Tages,
legt die Datei an und geht verloren. Die Velociraptor-Brücke (Befund 32) hat
seit ihrem Bau den Großteil dessen verloren, was sie je gemeldet hätte. Die
Atomic-Tests (T1053.003, T1098.004, T1562.004 Weg B) waren "detected", weil vor
jedem Test schon Dateien des Tages existierten: Test-Artefakte des Testens.
Befund 34 hatte das Verhalten als Test-Hinweis abgelegt ("Agent liest neue
Dateien vom Ende, für Tests frischen Diff erzeugen"). Es war eine tägliche
Erkennungslücke von Mitternacht bis zum ersten Event, je Quelle, je Client.

**Fix, Velociraptor-seitig:** Jede Quelle beider Event-Artefakte bekommt einen
zweiten Zweig via `chain(async=TRUE, a={diff…}, b={heartbeat})`. Der Heartbeat
tickt mit `clock(period=Period)` und schreibt nur in den ersten zwei Minuten
nach 00:00 UTC eine Zeile `Diff="heartbeat"` mit leeren Feldern:

```
WHERE now() - int(int=now() / 86400) * 86400 < Period * 2
```

(VQL kennt kein `%`.) Damit existiert jede Tagesdatei, bevor ein echtes Event
kommt. Wazuh 110187 (Level 0, `Diff=heartbeat`, Kind von 110180, **vor**
110181-110186 in der Datei, sonst trifft ein Heartbeat mit `Port 0` die
Port-Regel) schluckt sie. Zusätzlich `logcollector.vcheck_files=10` auf dem
Velociraptor-Host: Restlücke nach dem Heartbeat ~10 s statt ~60.

**VQL-Lehren dabei:** LET innerhalb einer Subquery lehnt der Parser ab
("unexpected token LET"); eine execve je Tick erreicht man, indem Stdout durch
`foreach`-Stufen nach innen gereicht wird (Nachtrag 33c, 3x nft → 1x, per
`ausearch` auf redcanary verifiziert). `chain(async=TRUE)` läuft in
CLIENT_EVENT-Artefakten parallel. `WHERE TRUE` als Testschalter für die
Heartbeat-Bedingung: beim Artefakt-Update je Quelle ersetzen, nicht nur die
letzte (Editor-Falle, hat eine Stunde gekostet).

**Nagelprobe 2026-10-12:** alle 10 Tagesdateien um 02:01-02:04 Ortszeit
angelegt, je 2 Heartbeats, erste Zeile 00:00:06-00:00:56Z (UTC-Tagesgrenze
bestätigt). `synctest` auf grafana (nur Heartbeats am Tag): `added probe` UND
`removed probe` im SIEM. Baseline (Listeners, AuthorizedKeys, Cron) abends mit
demselben Zweig nachgezogen, 10/10/10.

**Betriebsregel:** Beim Einspielen eines CLIENT_EVENT-Artefakts kurz zwei
Queries nebeneinander; einmal `removed`+`added` in derselben Sekunde gesehen.
Nach einem Update 90 s warten, bevor getestet wird.

Nachtrag 2026-10-15: Erstes Baseline-Event nach dem Heartbeat-Fix im SIEM: 10 × 110181 vom pi-hole um 11:56, alle fünf Dienst-Ports als „added“, v4 und v6. 
Ursache: Reboot, Velociraptor-Client vor den Diensten gestartet, erste Diff-Runde sah ein leeres System. Ohne Befund 39 wäre das Event verloren gewesen; mit ihm waren es zehn IRIS-Fälle. 
Fix im Artefakt: info().Uptime > 600 in der Listeners-Quelle. Offen: Name ist auf dem Pi null, netstat() liefert den Prozessnamen dort nicht.

---

### Befund 40: 1.124 Level-7-Alerts, weil redcanary wieder lief (2026-10-12)

**Symptom:** Top-1 im Tagescheck: `110190 T1562.004: Firewall-Werkzeug
aufgerufen durch auid 4294967295 (exe /usr/sbin/nft -j)`, 1.124 Stück, einer je
Minute.

**Ursache:** Die Stillregel 110189 (auid unset + `a1 = list`) deckte die
Artefakt-Form `nft -j list ruleset` nie ab, dort ist `a1 = -j`. Das fiel nicht
auf, weil redcanary, der einzige Host mit auditd, seit Freitag aus war. Heute
lief er, und FirewallState pollt jede Minute.

**Falscher erster Fix:** Ich hatte die Argumentreihenfolge im Artefakt auf
`list ruleset -j` gedreht, in der Annahme, das sei die alte Form. War es nicht
(die Datei vom Donnerstag hatte schon `-j list ruleset`), und nft nimmt Optionen
nur vor dem Kommando: "options must be specified before commands". Ergebnis:
leeres Stdout, Diff-Query blind, Heartbeats liefen weiter. Vom `synctest`
entdeckt (gar nichts kam, nicht mal `removed`), über Datastore → Ops-Log →
`nft` von Hand auf grafana eingegrenzt.

**Richtiger Fix:** Artefakt zurück auf `-j list ruleset`, mit Kommentar warum.
Zweite Stillregel 110188 in 0920: auid unset + `a1 = -j` + `a2 = list`, Level 0.
110189 bleibt für die nackte Form.

**Lehre:** Ein Vertrag zwischen zwei Systemen (Argumentreihenfolge hier,
Wazuh-Regel dort) gehört als Kommentar an beide Enden. Und: "einer je Minute
auf genau einem Host" ist die Signatur eines eigenen Pollers, keine Angriffs-
Signatur; der Tagescheck zeigt das jetzt in der Top-5.

### Nachtrag zu Befund 38: Umbau nach zwei Lookup-Aussetzern (2026-10-14)

**Strichliste:** 2026-10-12 15:21 und 2026-10-14 17:26 hat 110040 auf
`androidtvchannels-pa.googleapis.com` gezündet, obwohl die Domain in der CDB-
Liste steht und `not_match_key` sie hätte ausschließen müssen. Kein Restart,
kein Fehler im Manager-Log, dazwischen Dutzende korrekte Treffer von 110061.
Zwei Aussetzer in drei Tagen; die Schwelle aus Befund 38 war zwei.

**Umbau:** Die Liste wird nicht mehr in Frequenzregeln geprüft, sondern einmal,
sofort, in einer Vorfeld-Regel:

- 110011 (Level 1, `if_sid 110010`, `match_key` dns-telemetry): Block einer
  bekannten Rausch-Domain. Steht in der Datei VOR 110040 und 110061.
- 110061 (Level 5, 30/600): `if_matched_sid 110011`, ohne Liste.
- 110040 (Level 7, 30/300): `if_matched_sid 110010`, ohne Liste.

Wirkung eines Lookup-Aussetzers: Das gelistete Event wird ein gewöhnliches
110010 und zählt für 110040 als eins von dreißig in fünf Minuten. Ein einzelner
Aussetzer kann keinen Alarm mehr auslösen; nur ein dauerhaft kaputter Lookup
würde es, und das wäre dann ein echter Befund. Logtest: TV-Domain → 110011 ×30,
110061; erfundene Domain → 110010 ×30, 110040 mit MITRE.

**Warum der Lookup aussetzt,** ist weiter offen. Mehrfädiges analysisd, geteilte
CDB; zwei Beobachtungen reichen nicht für eine Aussage. Der Umbau macht die
Frage unwichtig, das ist der Sinn.

**Liste:** `ws.batch.com` (Push-SDK, Handy) ergänzt. `trafficjunky.net` bewusst
nicht: Werbenetz-Pixel aus Browsern sind eine andere Klasse als Geräte-
Telemetrie; Zählung läuft bis 2026-10-27, dann Entscheidung zwischen Liste und
Muster-Regel (`pcre2` auf bekannte Werbenetz-Endungen vor 110040).

**Kleinkram vom selben Tag:** 533 auf pi-hole (11/Tag) waren UDP-Zufallsports
von pihole-FTL und Avahi; Netstat-Kommando in der lokalen ossec.conf des Pi um
`grep -vE '^udp6? [^ ]+:[3-6][0-9]{4} '` ergänzt (nicht im Repo, nicht in
sync-check). Syscheck-Ignores in der default-agent.conf für
`/etc/velociraptor.writeback.yaml(.bak)`, `/etc/fake-hwclock.data` und
`/etc/pihole/pihole-FTL.db*`: Daten in /etc, keine Konfiguration. 550 danach
nur noch pve-Backup und pmxcfs. Watchdog: `ChS` auf `optional_agents`, der
Arbeitsplatz-Agent fällt nach dem Standby für Minuten aus.

### Befund 41: AppArmor 52002 drei Tage Top-5 (2026-10-15)


AppArmor 52002 drei Tage Top-5: auf dem Manager das zu enge Ubuntu-Profil who (passwd/nsswitch), 
lokal ergänzt; auf dem Arbeitsplatz Snap-Confinement (Firefox igfx, KeePassXC USB ohne raw-usb, Proxy nach Refresh), 
Override 110198 L1 eng auf die drei Muster, /etc/shadow bleibt Level 3. Lehre: 52002 nicht absenken, Verursacher benennen; einer davon war ein Systemfehler.

### Nachtrag zu Befund 16: Triage-Evalset auf der RX 7900 XT, Zweitmeinung getauscht (2026-10-16)

**Anlass:** Neue Hardware auf llm (5800X3D, RX 7900 XT 20 GB, ROCm statt
Vulkan, `OLLAMA_CONTEXT_LENGTH=8192`). Damit passen 24–32B-Modelle mit Kontext
in den Speicher; im September liefen die zum Teil auf der CPU und sind daran
gescheitert, nicht an der Aufgabe. Gleicher Prompt (`run-triage-eval.py`
importiert die Logik aus `custom-iris.py`), gleiche sieben Fälle, zwei Läufe,
15 Modelle, 210 Triagen, über Nacht auf dem llm selbst (nicht vom Laptop: der
geht aus).

| Modell | Treffer | stabil | Fehlurteile | Median s |
|---|---|---|---|---|
| gemma4:12b (Triage) | 14/14 | 7/7 | – | 13 |
| gemma4:31b | 14/14 | 7/7 | – | 43 |
| gemma4:26b | 12/14 | 7/7 | 05 → suspicious | 22 |
| cogito:32b | 12/14 | 7/7 | 06 → malicious | 34 |
| qwen3:32b | 12/14 | 7/7 | 05 → benign | 41 |
| cogito:14b | 12/14 | 7/7 | 05 → benign (95 %) | 14 |
| qwen3.8:27b | 12/14 | 5/7 | 02, 05 wechselnd | 29 |
| gpt-oss-safeguard:20b | 11/14 | 6/7 | 04 einmal benign, 05 | 22 |
| gpt-oss:20b (Zweitmeinung bis heute) | 10/14 | 6/7 | 01 → benign (2x), 05 wechselnd | 20 |
| qwen3:14b | 10/14 | 7/7 | 02, 05 → benign | 16 |
| gemma4:e4b | 10/14 | 7/7 | 02, 05 | 8 |
| glm4:9b | 9/14 | 4/7 | 3 Timeouts, 03, 07 | 14 |
| mistral-small3.2:24b | 8/14 | 7/7 | 02, 05, 07 → suspicious | 22 |
| granite3.3:8b | 6/14 | 7/7 | fast alles suspicious | 9 |
| qwen3:30b-a3b | 4/14 | 7/7 | fast alles benign | 22 |

Fälle: 01 Tunneling mit veralteter TI (erw. suspicious/malicious), 02 Tunneling
mit frischem VT-Treffer (malicious), 03 Hersteller-Telemetrie (benign),
04 NRD+DGA ohne Bestätigung (suspicious/malicious), 05 Honeypot-Brute-Force
ohne TI (malicious), 06 fremdes Docker-Image (suspicious), 07 MISP-Treffer auf
Großdomain (benign).

**Entscheidungen:**

- Triage bleibt **gemma4:12b**: fehlerfrei, stabil, 13 s. gemma4:31b ist
  ebenfalls fehlerfrei, aber dreimal so langsam und bringt auf diesem Set
  nichts dazu. Der Prompt aus Befund 16 und dieses Modell passen zusammen.
- Zweitmeinung **gpt-oss:20b → cogito:32b**. gpt-oss sagt bei Fall 01 zweimal
  `benign` (78 %): den Verhaltensbefund übersehen, weil die TI alt ist; genau
  der Fehler, den das Set sichtbar machen soll. Dazu instabil bei 05. Ein
  `llm-disagree` von gpt-oss war damit eher ein Hinweis auf gpt-oss als auf
  den Fall. cogito:32b: 12/14, stabil, einziger Fehler Fall 06 `malicious`
  statt `suspicious`, also in die Richtung, in die eine Zweitmeinung irren
  darf (schärfer, nie stiller); andere Modellfamilie als Gemma, also eine
  zweite Sicht statt derselben Sicht zweimal. Preis: 34 s statt 20, und mit
  19 GB kein Platz neben Gemma, ein Modellwechsel je Alert. cogito:14b wäre
  ohne Wechsel möglich, aber `benign` mit 95 % beim Honeypot-Brute-Force ist
  für eine Zweitmeinung der schlimmste Fehler: Sie würde ein richtiges
  `malicious` anzweifeln.
- Gate bleibt nimble (nicht Teil dieses Laufs).

**Beobachtungen:**

- **Fall 05 trennt das Feld.** Acht von fünfzehn Modellen stufen Brute Force
  gegen den Honeypot ohne Threat-Intel ab, vier auf `benign`. Das ist der Fall,
  der im Betrieb am häufigsten vorkommt. Kandidaten, die hier versagen, sind
  für diesen Stack raus, egal wie sie sonst abschneiden.
- **Konfidenz ist wertlos.** Fast jedes Modell ist bei Fehlurteilen so sicher
  wie bei Treffern (gpt-oss 78/78, mistral 76/75, granite 85/85), cogito bei
  Fehlern sogar sicherer (91/95). Ein Konfidenz-Schwellwert in der Pipeline
  würde nichts filtern. Die Zahl bleibt im IRIS-Fall als Information, trägt
  aber keine Entscheidung.
- qwen3:30b-a3b (MoE) sagt zu fast allem `benign`, granite3.3 zu fast allem
  `suspicious`: beide haben einen Standardwert, keine Meinung. glm4:9b lief
  dreimal in den 300-s-Timeout.
- Sieben Fälle sind klein; 14/14 ist kein Beweis, die Rangfolge ist belastbar.
  Das Set wächst um einen Fall, sobald ein echter Alert eine Lücke zeigt
  (Kandidat: der Reboot-Burst aus Befund 39, 10 x 110181 "added" auf einem
  Host innerhalb einer Minute, erwartet `benign`).

**Umsetzung:** `/var/ossec/etc/custom-iris.json`,
`"llm_model": ["gemma4:12b", "cogito:32b"]`. Kein Restart, die Integration
liest die Datei je Aufruf. Eine Woche `llm-disagree` im Integrations-Log
zählen; der Anteil sollte steigen (cogito ist strenger), und die Fälle dahinter
sollten die sein, bei denen eine zweite Meinung etwas beiträgt. Ergebnisse:
`tests/triage/results-20261015-2155.jsonl`.

**Hardware-Zeile:** llm seit 2026-10-15: Ryzen 7 5800X3D, RX 7900 XT 20 GB
(gfx1100, ROCm offiziell, kein `HSA_OVERRIDE`), 32 GB DDR4-3600. Gemma 4 12B:
60 t/s Generierung, 1.080 t/s Prompt, 257 W unter Last, Lüfter 30 %.
`OLLAMA_VULKAN=1` entfernt (wirkungslos geworden, Ollama nimmt ROCm), Kontext
auf 8192 (die Integration schickte das schon mit, `ollama run` nicht).

### Befund 42: Was die Triage den ganzen Tag macht — IRIS-Liste gelesen (2026-10-16/17)

**Anlass:** Beim Suchen nach dem Grund für einen Sprung der IRIS-Alert-IDs die
Alert-Liste der letzten zwei Tage durchgelesen (40 Alerts, #1256–#1294). Der
ID-Sprung blieb unerklärt (der Eval-Lauf aus Befund 16 war es nicht: zwischen
21:38 und 04:56 kein einziger Alert, keine `.example`-Domain). Die Liste selbst
war der Fund: Vier Rauschquellen, alle Level 7, alle mit Gate, Triage-LLM und
Zweitmeinung, zusammen rund 30 der 40 Fälle.

| Quelle | Regel | Alerts | Was es war | Fix |
|---|---|---|---|---|
| `amd-keyid-<hash>.microsoftaik.azure.net` vom llm, `<50 Zeichen>.scf.usercontent.goog` vom Android-Handy | 110022 oversized label | 14 | AMD-TPM-Attestierung gegen Microsofts AIK-Dienst (seit dem Hardware-Umbau); Google-Content-Hosting | CDN-Suffixe in der lokalen 0109 (Gate 110003): `usercontent.goog`, `microsoftaik.azure.net`. Logtest: Zeile endet bei 110002/L0, wie `04-pihole-cdn-negative` |
| Fritzbox „WLAN-Autokanal … geändert“ | 110145 settings_changed | 3 | Router wechselt den 5-GHz-Kanal, das ist sein Job | Kindregel 110156 (`regex WLAN-Autokanal`), L3; andere settings_changed bleiben 7 |
| `data.logentries.com` 30+/5 min, nachts um 5 | 110040 | 3 | Rapid7-InsightOps-Telemetrie eines Geräts | Liste dns-telemetry |
| 192.168.178.1 → Canary Port 80, `/index.html`, UA not supplied | 110132 honeypot touched | 1 | Die Fritzbox tastet Geräte fürs Heimnetz-Bild ab | Kindregel 110136: Gateway-IP + logtype 3000 (HTTP ohne Login) → L3; SSH/VNC/Redis vom Gateway und jeder Login bleiben 8/10 |
| `signaler-pa.youtube.com` von ChS, `gateway.fe2.apple-dns.net` vom iPhone | 110091 beaconing | 2 | App-Heartbeats | Analytics-Allowlist auf dem Pi: `youtube.com`, `apple-dns.net` |

**Der Satz, der hängen bleibt:** Zum Honeypot-Touch des Routers sagte Gemma
*MALICIOUS 95 %, Host 192.168.178.1 isolieren.* Der Host ist der Router. Das
Modell kennt die Infrastruktur nicht, weil der Prompt sie nicht nennt. Nachtrag
offen: eine Zeile im Triage-Prompt mit den Infrastruktur-Adressen (Gateway,
Pi-hole, Manager, llm) und dem Hinweis, dass Änderungen dort Betrieb sind und
Isolation keine Option. Gehört in `custom-iris.py`, mit sync-check davor.

**Zweitmeinung, Nachtrag zu 16:** Die 7 `llm-disagree` vom 16.10. waren alle noch
gpt-oss (Umstellung auf cogito erst am Nachmittag). Lesbar in der Liste: gpt-oss
widerspricht mit demselben Absatz („warrants a human investigation“), egal ob
Pi-hole-Port 53 oder YouTube-Heartbeat. Das bestätigt den Tausch; über cogito
wissen wir nach einem Tag noch nichts.

**Nebenfund, Dubletten:** Beim Einbau von 110156 war 110149 kurz doppelt
vergeben (die Datei endet bei 110155, ich hatte die Nummer ohne Blick in die
Datei gewählt). `grep -ohE 'rule id="[0-9]+"' rules/*.xml | sort | uniq -d`
fand drei Dubletten live: 110003, 110072, 110174, alle Overrides mit
`overwrite="yes"` in der lokalen 0109, also Absicht. 110174 trug ein
Verfallsdatum („Lernphase bis 2026-10-11, danach entfernen“), das sechs Tage
überschritten war: entfernt, neue WLAN-Clients wieder Level 8. sync-check prüft
jetzt vor jedem pull auf Dubletten: Overrides werden gelistet, echte Dubletten
(zwei Definitionen ohne overwrite, eine davon tot) blockieren. Die lokale 0109
wird geprüft, aber nie verglichen oder gepullt (`RULES_LOCAL`); ein früherer
pull hatte sie als „only-live“ ins Repo-Verzeichnis kopiert, die `.gitignore`
hatte sie, Git nie.

**Lehre:** Der Tagescheck zählt, was feuert. Die IRIS-Liste zeigt, was
*kostet*: Jeder dieser 30 Fälle war ein Gate-Aufruf, ein Triage-LLM, eine
Zweitmeinung und ein Fall, den jemand lesen muss. Einmal pro Woche die Liste
lesen, nicht nur die Zahlen, ist ab jetzt Teil des Betriebs.

### Befund 43: Triage-Spool — der llm-Rechner darf aus sein (2026-10-17)

**Anlass:** Der llm-Rechner (5800X3D, RX 7900 XT) zieht im Leerlauf rund 70 W,
damit er für ein paar Dutzend Triage-Anfragen am Tag bereitsteht. Bisher war
„aus“ gleichbedeutend mit „kein Urteil“: `custom-iris` sondiert `/api/tags`
mit 3 s Timeout, schreibt `llm: unreachable` in den Alert, und das war's. Der
Fall lag in IRIS ohne Gate, ohne Triage, ohne Zweitmeinung, für immer.

**Umbau:** Die Integration bleibt synchron und der IRIS-Alert entsteht wie
bisher sofort (Push kommt pünktlich, nichts geht verloren). Neu bei
`unreachable`: Tag `llm-pending`, und Alert plus bereits gelaufenes Enrichment
(RDAP, VT, MISP, PTR) landen als eine JSON-Datei je Fall unter
`/var/ossec/var/triage-spool/`, Name `<UTC>-<IRIS-ID>.json`, atomar über
tmp + rename. Ein systemd-Timer (`triage-spooler.timer`, alle 120 s, läuft als
`wazuh`) startet `triage-spooler`: leerer Spool oder keine Antwort von
`/api/tags` heißt stiller Exit, keine Logzeile. Antwortet die API, werden die
Dateien in Reihenfolge abgearbeitet, mit denselben Funktionen wie die
Integration selbst (`run_triage()`, `triage_text()`, per Import aus
`custom-iris`, nichts kopiert): Gate, Triage, Zweitmeinung. Das Ergebnis geht
als Kommentar an den IRIS-Alert („Deferred triage: … delivered 2h13m later“),
`llm-pending` wird gegen `dm-…`/`llm-…` getauscht, `alert_context.enrichment`
nachgezogen, Datei gelöscht. API-Key und Hook-URL liest der Spooler aus dem
`<integration>`-Block der `ossec.conf`, es gibt keine zweite Kopie.

Drei Entscheidungen, bewusst so: Der Spooler weckt nichts (kein WoL, der
Mensch entscheidet, wann 400 W anspringen). Kein Fall verfällt, eine Triage
drei Tage später ist immer noch eine Triage. Und das Urteil kommt als
Kommentar, nicht in die Beschreibung, damit „nachgereicht“ sichtbar bleibt.

Randfälle: Geht der Host mitten im Lauf wieder aus, bricht der Spooler ab,
der Rest wartet. LLM-Fehler (Timeout, kaputtes JSON) werden bis zu dreimal
versucht, dann wird der Fehler selbst als Kommentar geliefert. IRIS-Fehler
lassen die Datei liegen, nächster Tick. Ein Alert, der inzwischen gelöscht oder
gemerged wurde (HTTP 404), wird verworfen, bevor LLM-Zeit draufgeht. Ein
flock verhindert zwei parallele Läufe; der Zähler `attempts` wird vor dem Lauf
hochgesetzt, damit ein Absturz mitzählt.

**Nagelprobe:** Den logentries-Fall vom 16.10. (Befund 42) mit
`triage-spooler --replay` bei abgeschaltetem Rechner eingespielt: IRIS-Alert
1305 mit `llm-pending`, Spool-Datei da. Rechner an, Timer gewartet: nach dem
nächsten Tick Kommentar am Alert, Tags `dm-suspicious llm-suspicious
llm-disagree`, Spool leer. Dass `--list` dabei kurz `attempts 1` zeigte, war
der laufende Tick (gemma plus cogito brauchen rund eine Minute), kein Fehler.

**Betrieb:** `triage-spooler --list` zeigt die Warteschlange mit Alter;
`triage-spooler --replay <alert.json>` spielt einen Alert durch die
Integration, ohne den Key in die Shell zu nehmen. Tagescheck zählt jetzt
„Triage-Spool wartend“ und „nachgereicht heute“. Der Watchdog führt den Agent
`llm` als optional, sonst wäre „down“ die neue Dauerzeile. sync-check vergleicht
Spooler und beide Units gegen das Repo.

**Lehre:** Ein SOC-Baustein, der nur funktioniert, wenn ein Gaming-PC durchläuft,
ist keine Architektur, sondern eine Stromrechnung. Die Entkopplung hat die
Integration nicht komplizierter gemacht, sie hat nur die Stelle, an der das
Urteil verloren ging, durch eine Datei ersetzt.

**Nachtrag, gemessen statt geschätzt (2026-10-17, später Abend):** Zwei
FRITZ!DECT 200 hängen seit heute an der Rechner-Leiste (llm, PVE, drei
Displays, Fritzbox) und am Schrank (die Raspis). Die Werte kommen über den
vorhandenen fritzbox_exporter in Prometheus: Dienst `X_AVM-DE_Homeauto:1`,
Aktion `GetGenericDeviceInfos` mit festem Index 0 und 1 (keine Zähl-Aktion im
Dienst, deshalb kein `isIndex`), Rohwerte in 0,01 W, Wh und 0,1 °C, skaliert
wird in der Abfrage. Zehn Einträge, `infra/fritzbox_exporter/add-dect-metrics.py`
hängt sie an die `metrics.json`; die liegt jetzt mit im sync-check (relay hat
kein sudo, der Abgleich prüft das seit heute).

Die Messung, um die es ging: Rechner-Leiste 126,5 W mit llm im Leerlauf,
60,0 W ohne. **66,5 W** für einen Rechner, der auf Triage-Anfragen wartet, rund
580 kWh im Jahr. 

### Korrekturen (2026-10-09)

- **Baseline-Abdeckung ist 9/9, nicht 7/9.** Die Zaehlung vom 06.10. zaehlte
  Hosts mit einem Resultat-Baum (= mindestens eine gemeldete Aenderung), nicht
  Hosts mit aktivem Artefakt. pi-hole und watchdog fuehren die Baseline
  (monitoring_logs von heute, fehlerfrei), hatten nur noch nie eine Aenderung.
- **Velociraptor-Clients: 12 -> 9.** Drei Leichen geloescht (redcanary x2 aus
  Rollbacks vor dem Enrollment-Zeitpunkt, alter 24.04-Sensor vor dem Umbau).
  Merker: Rollback auf einen Snapshot VOR der Client-Enrollment-Zeit erzeugt
  beim Boot einen neuen Client mit neuer ID.
- Baseline-Artefakt: Beschreibung "alle 5 Min" -> "alle 60 Sekunden
  (Parameter Period)", per GUI. Hinweis an mich selbst: `grep -rl` im
  Datastore trifft auch Server.Audit.Logs, die die Definition zitieren;
  nie `sed -i` auf ein Suchergebnis ohne vorher zu schauen, was es ist.

### Kleinkram (neu, 2026-10-08)

2026-10-15: Wazuh Manager und alle Agenten auf 4.14.9. Zu prüfen: Befund 39 (Logcollector liest neue Wildcard-Dateien vom Ende) und Befund 38 (CDB-Lookup-Aussetzer) wurden auf 4.14.8 beobachtet; nach dem Update einmal synctest auf einem Client ohne Tagesdatei und die 110040-Strichliste weiterführen. Der Heartbeat bleibt unabhängig davon drin. 4.14.9 ändert nichts an 38/39

