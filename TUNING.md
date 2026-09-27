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
