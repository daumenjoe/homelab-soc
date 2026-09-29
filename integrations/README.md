# Integrationen

## DFIR-IRIS (`custom-iris.py`)

Wazuh Custom Integration: Alerts ausgewählter Regeln werden als IRIS-Alert angelegt
(Titel mit Regel-ID, Severity aus dem Level, Domain und Client als IOCs, der komplette
Wazuh-Alert als Kontext). Der Analyst entscheidet in IRIS per *Escalate*, ob daraus ein Fall wird.

Installation auf dem Manager:

    install -o root -g wazuh -m 750 custom-iris.py /var/ossec/integrations/custom-iris

Konfiguration in `/var/ossec/etc/custom-iris.json` (root:wazuh 640, Vorlage `custom-iris.json.example`): IRIS-Kunden-ID, VirusTotal-Key, Dashboard-URL.

**Anreicherung (v2):** Jeder Alert wird vor dem Anlegen angereichert – RDAP (Registrierungsdatum, Domainalter, Tag `nrd` unter 30 Tagen), VirusTotal (Engines-Statistik, Kategorien; Tag `vt-flagged`, ab drei Treffern eine Schweregradstufe höher), Reverse-DNS des Clients (Gerätename). Kurzfassung in der Beschreibung, alles Weitere im Alert-Kontext. Jede Quelle ist best-effort: fällt sie aus, steht der Grund im Kontext, der Alert kommt trotzdem an.

**MISP (v2.2):** Domain und registrierbare Domain werden gegen gespeicherte Events (`/attributes/restSearch`) und den Feed-Cache (`/feeds/searchCaches`) geprüft. Treffer: Tag `misp-hit`, Schweregrad eine Stufe höher, Event-Titel mit Link im Kontext. Kein Treffer steht ebenfalls im Alert. Verfallene Treffer (MISP-Decay-Score `decayed`, oder Event älter als `misp_stale_days` ohne Score) bekommen `misp-stale` statt `misp-hit` und erhöhen den Schweregrad nicht – Kontext, keine Eskalation. Das Skript nutzt ein Dienstkonto mit Read-Only-Rolle und IP-gebundenem Auth-Key.

**VirusTotal-Budget:** lokaler Zähler (`/var/ossec/var/custom-iris-vt.json`, dateigesperrt, damit parallele Läufe nicht überziehen) mit den Free-Tier-Grenzen 4/min und 500/Tag; bei Überschreitung wird VT übersprungen, ein HTTP 429 pausiert VT bis zum Tageswechsel. `custom-iris --vt-quota` fragt den echten Stand ab und gleicht den Zähler an.
In der `ossec.conf` (API-Key nur dort, nie im Repo):

    <integration>
      <name>custom-iris</name>
      <hook_url>https://<iris-host></hook_url>
      <api_key>...</api_key>
      <rule_id>110026,110080,110099</rule_id>
      <alert_format>json</alert_format>
    </integration>

Handtest ohne Manager-Neustart:

    /var/ossec/integrations/custom-iris <alert.json> <api-key> https://<iris-host>

Log: `/var/ossec/logs/integrations.log`. Ende-zu-Ende-Test: Zeile aus `tests/cases/29-analytics-tunneling.log`
an das Analytics-Log auf dem Pi anhängen, der Alert erscheint in IRIS.
