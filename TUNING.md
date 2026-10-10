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

---

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
- 292 x AppArmor DENIED auf dem Laptop (ChS) an einem Tag. Profil pruefen:
  `journalctl -k | grep apparmor=\"DENIED\" | grep -oE 'profile=\"[^\"]*\"' | sort | uniq -c`
- Regeldatei-Uebersicht: neue Zeile `0920-defense_evasion_rules.xml | 110189-110192 | auditd`
