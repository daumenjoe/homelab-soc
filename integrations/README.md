# Integrationen

## DFIR-IRIS (`custom-iris.py`)

Wazuh Custom Integration: Alerts ausgewählter Regeln werden als IRIS-Alert angelegt
(Titel mit Regel-ID, Severity aus dem Level, Domain und Client als IOCs, der komplette
Wazuh-Alert als Kontext). Der Analyst entscheidet in IRIS per *Escalate*, ob daraus ein Fall wird.

Installation auf dem Manager:

    install -o root -g wazuh -m 750 custom-iris.py /var/ossec/integrations/custom-iris

`CUSTOMER_ID` im Skript an den IRIS-Kunden anpassen (`GET /manage/customers/list`).
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
