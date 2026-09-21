# Erwartete Ergebnisse

Erzeugt mit `run-logtest.sh --table` – nicht von Hand pflegen.

| Fall | Beschreibung | Zeilen | Erwartete Rule-IDs |
|---|---|---|---|
| `01-pihole-blocked.log` | Gravity-Block einer externen Domain | 1 | 110010 |
| `02-pihole-txt-burst.log` | TXT-Burst eines Clients auf wechselnde Subdomains (DNS-Tunneling, 110021) | 30 | 110025 110026 |
| `03-pihole-internal-negative.log` | Negativtest – interne Namen dürfen Gate 110002 nicht passieren | 3 | 110000 |
| `04-pihole-cdn-negative.log` | Negativtest – CDN-Suffix darf Gate 110003 nicht passieren (keine Heuristik-Alerts) | 2 | 110002 |
| `05-pihole-longlabel-cdn-negative.log` | Negativtest – langes, lesbares Label unter bekanntem CDN-Suffix löst 110022 nicht aus (query- und reply-Zeile) | 2 | 110002 |
| `06-pihole-longlabel-positive.log` | Überlanges Label feuert 110022 – aber nur auf der query-Zeile, nicht auf der reply-Zeile | 2 | 110002 110022 |
| `07-pihole-txt-burst-plain.log` | TXT-Burst mit unauffälligen Namen – zählt über 110020 auf 110021 | 25 | 110020 110021 |
| `08-pihole-dga-positive.log` | Klassisches DGA-Muster in der Hauptdomain feuert 110024 | 2 | 110024 |
| `09-pihole-dga-subdomain-negative.log` | Negativtest – zufällig aussehende Subdomains seriöser Domains (CDN, Hashes, deutsche Komposita) lösen 110024 nicht aus | 3 | 110003 |
| `10-unbound-normal-negative.log` | Negativtest – normale, schnelle, kleine Antwort löst keinen Alert aus | 1 | 110070 |
| `11-unbound-dnssec-bogus.log` | DNSSEC-Validierungsfehler feuert 110071 | 1 | 110071 |
| `12-unbound-servfail-single.log` | Einzelner SERVFAIL: info-Zeile und zugehörige error-Zeile | 2 | 110070 110072 |
| `13-unbound-servfail-storm.log` | 20 schnelle SERVFAILs in 20 s zählen auf 110073 | 20 | 110072 110073 |
| `14-unbound-servfail-storm-slow.log` | 20 LANGSAME SERVFAILs (Timeouts) – zählt 110073 trotzdem? Prüft Maskierung durch 110075 | 20 | 110072 110073 |
| `15-unbound-large-response.log` | Antwort ab 1000 Bytes feuert 110074 | 1 | 110074 |
| `16-unbound-slow.log` | Auflösung über 5 s feuert 110075 | 1 | 110075 |
| `17-unbound-error.log` | Allgemeine Unbound-Fehlermeldung feuert 110076 | 1 | 110076 |
| `18-unbound-restart.log` | Neustart des Resolvers feuert 110077 | 1 | 110077 |
| `20-analytics-beaconing.log` | pihole-analytics Beaconing-Finding (JSON-Event) | 1 | 110091 |
| `21-analytics-beaconing-blocked.log` | Beaconing auf geblockte Domain – 110092, bewusst nur Level 6 (Verbindung kam nie zustande) | 1 | 110092 |
| `22-analytics-dga.log` | DGA-Finding feuert 110093 | 1 | 110093 |
| `23-analytics-nxdomain.log` | NXDOMAIN-Sturm pro Client feuert 110094 | 1 | 110094 |
| `24-analytics-nrd.log` | Newly Registered Domain feuert 110095 | 1 | 110095 |
| `25-analytics-heartbeat.log` | Heartbeat mit geladener NRD-Liste: nur 110096 (Level 1) | 1 | 110096 |
| `26-analytics-heartbeat-no-nrd.log` | Heartbeat ohne NRD-Liste feuert 110098 | 1 | 110098 |
| `27-analytics-error.log` | Fehler des Analytics-Laufs feuert 110097 | 1 | 110097 |
| `28-analytics-correlation.log` | Korrelation NRD + DGA/Beaconing fuer denselben Client feuert 110099 (Level 12) | 1 | 110099 |
| `30-pihole-long-fqdn.log` | FQDN ab 70 Zeichen (kein Label ab 40) feuert 110023 | 1 | 110023 |
| `31-pihole-nxdomain-storm.log` | 30 NXDOMAIN-Antworten in 30 s zählen auf 110031 | 30 | 110030 110031 |
| `32-pihole-blocklist-beaconing.log` | 35x dieselbe geblockte Domain in unter 5 min zählt auf 110040 | 35 | 110010 110040 |
| `33-pihole-doh.log` | Auflösung eines DoH-Endpunkts feuert 110050 | 1 | 110050 |
| `34-pihole-abuse-tld.log` | Query auf Missbrauchs-TLD feuert 110060 | 1 | 110060 |
