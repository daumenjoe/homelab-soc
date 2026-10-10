# Case Study: Tote Sensor-Anbindung bei Routine-Review entdeckt

**Datum:** 2026-10-06
**Umgebung:** Homelab Detection Engineering (Wazuh SIEM, Velociraptor EDR,
Suricata, 15 Agents)
**Kurzfassung:** Ein geplanter Volumen-Review nach einem Sensor-Umbau deckte
auf, dass ein kompletter EDR-Sensor (Velociraptor, 9 Clients) seit der
Einrichtung nie Daten ins SIEM geliefert hatte. Erkennungen waren nur in der
Velociraptor-GUI sichtbar, nie im zentralen Alerting. Ursachen isoliert,
behoben und End-to-End verifiziert.

---

## Auslöser

Nach dem Umbau des Netzwerk-Sensors auf eine neue OS-Version stand ein
Volumen-Review an: Stimmen die Alert-Zahlen, oder erzeugt der neue Sensor
unerwartetes Rauschen? Im Grafana-Dashboard fielen in der 7-Tage-Ansicht zwei
Regeln mit je ~60.000-80.000 Treffern auf. Diese entpuppten sich als Altlast
des alten Sensors (Umstellung auf 24h-Ansicht bestätigte: der neue Sensor war
leise).

Beim Durchgehen der Alert-Quellen fiel aber etwas anderes auf: Die
Velociraptor-Erkennungsregeln (neue Listening-Ports, neue SSH-Keys, neue
Cron-Einträge) tauchten im Alert-Log **überhaupt nicht** auf — auch nicht mit
Treffer-Zahl 0, sondern komplett abwesend.

## Diagnose (Quelle → Senke)

Methodisch von der Datenquelle zur Senke, nicht umgekehrt:

1. **Regel-Ebene:** `grep` auf die vier Velociraptor-Regel-IDs im Alert-Log →
   null Treffer, je. Die Regeln hatten nie gefeuert.
2. **Verwechslung ausgeschlossen:** Eine erste Suche nach dem String
   "velociraptor" fand 54 Treffer — stellte sich als PAM-Login-Sessions des
   velociraptor-Dienstusers heraus (Regel 5501/5502), nicht als Erkennungen.
   Lehre: auf Regel-IDs filtern, nicht auf frei assoziierte Strings.
3. **Transport-Ebene:** Durchsicht aller `<localfile>`-Eingänge des Managers →
   kein einziger verweist auf Velociraptor-Daten. Es gab schlicht keinen Kanal.
4. **Quell-Ebene:** Im Velociraptor-Datastore lagen die Ergebnisse sehr wohl —
   inklusive der Cron-Testzeile eines früheren Atomic-Tests, mit Zeitstempel.
   Der Sensor *arbeitete*, nur niemand holte die Ergebnisse ab.

**Befund:** Reine Integrationslücke. Beide Werkzeuge funktionsfähig, die Brücke
zwischen ihnen fehlte. Und zwar nicht, weil sie nie gebaut worden wäre: Zwei
Tage zuvor hatte ein Atomic-Test noch einen Datastore-ACL-Fehler aufgedeckt,
der den Wazuh-Agent beim Lesen der Velociraptor-Ergebnisse aussperrte — es gab
also einen Lesepfad. Der Konfigurationsblock lebte lokal auf dem Host und wurde
beim nächsten Sync der Agent-Gruppenkonfiguration stillschweigend überschrieben.
Eine Konfiguration, die wieder verschwindet, ist das gefährlichere Muster als
eine, die nie da war.

Ein zweiter Verdacht aus dem ersten Tag hielt der Prüfung nicht stand: Die
Basis-Erkennungsregel stand auf Alarm-Level 0, und ich hatte angenommen, dass
Wazuh damit die Regel verwirft und abgeleitete Regeln nie greifen. Das stimmt
nicht — Level 0 heißt "nicht loggen", nicht "nicht matchen"; Wazuhs eigene
auditd-Sammelregel 80700 ist Level 0 und ihre Kinder feuern. Die Änderung auf
Level 2 blieb (schadet nicht), aber die Ursache war allein die Brücke.

## Behebung

1. **Brücke:** `<localfile>` auf dem Velociraptor-Host, der den
   Monitoring-Resultat-Baum des Datastores als JSON liest und über den
   bestehenden, verschlüsselten Wazuh-Agent-Kanal zum Manager schickt. Keine
   neue Netzwerkfreigabe nötig.
2. **Verankerung:** Der Block liegt seitdem in der Agent-Gruppenkonfiguration
   (ein `localfile` je Quelle), nicht mehr lokal auf dem Host, und ein
   Abgleichskript prüft Repo gegen Live-Systeme.
3. **Verifikation:** Auf einem überwachten Host einen Test-Port geöffnet →
   Velociraptor-Diff → Datastore → Agent → Manager → **Alert feuerte** (neuer
   Listening-Port, Level 8). Erstmals lief ein Velociraptor-Event
   Ende-zu-Ende ins SIEM.

## Nachgelagerter Stolperstein (gleicher Tag, Weg-A-Erkennung)

Beim Bau einer zweiten Erkennung (auditd-basiert, Firewall-Manipulation
T1562.004) griff eine Regel trotz korrekter Felder nicht. Ursache:
**Regel-Lade-Reihenfolge.** Die Custom-Regeldatei (Präfix 0110) lud *vor* der
Standard-auditd-Regeldatei (0365), daher war die Parent-Regel 80700 zum
Parse-Zeitpunkt unbekannt und das `if_sid`-Anchoring schlug fehl. Umbenennen auf
Präfix 0910 (lädt nach 0365) löste es. Live verifiziert: Werkzeug-Aufruf →
Level 7, `nft flush` → Level 12.

## Lehren

- Ein Sensor, dessen Events das SIEM nicht erreichen, ist eine blinde Stelle —
  unabhängig davon, wie gut die lokale Erkennung ist. "In der Tool-GUI sichtbar"
  ist nicht dasselbe wie "im SIEM korreliert".
- Reviews nach Infrastruktur-Änderungen zahlen sich aus: Dieser Fund kam nicht
  aus einem Alarm, sondern aus dem routinemäßigen Soll-Ist-Abgleich.
- Von der Quelle zur Senke debuggen. Hätte man bei der Regel angefangen, hätte
  man die Regel verdächtigt — dabei war sie korrekt, nur nie mit Daten versorgt.
- Erkennungen mit realistischen Angriffs-Artefakten testen: Ein Test mit einem
  hohen Port lief ins Leere, weil ein bewusst gesetzter Rausch-Filter
  (High-Ports) genau das abfängt — der Filter funktionierte, der Test war falsch
  gewählt. Niedriger Port (= echter Dienst/Backdoor) zeigte die Erkennung sofort.
- Wazuh-Spezifika, einmal gelernt: Level-0-Parents verwerfen die Kette;
  Regeldatei-Reihenfolge entscheidet über `if_sid`-Sichtbarkeit; `logtest`
  evaluiert anders als der Live-Daemon (beide gegenprüfen).
