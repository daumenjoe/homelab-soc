# Infrastruktur

## Mail-Relay (`setup-relay.sh`)

Ein Postfix-LXC ist der einzige Ausgang für Mails aus dem Homelab. Er nimmt aus dem LAN an,
schreibt Absender auf `<host>@<domain>` um, liefert per SASL/STARTTLS bei einem
Transaktions-Dienst ab (SPF, DKIM und DMARC liegen in der DNS-Zone der Domain) und
kennt als einziger die Zugangsdaten. Proxmox (`relayhost`), Wazuh (`<global>`-Mailblock,
`email_alert_level` 10) und weitere Hosts liefern dort ohne Auth ab.

    SMTP_USER=... SMTP_PASS=... DEST=<ziel-postfach> ./setup-relay.sh

Anlass war Befund 12 in `TUNING.md`: Die Beaconing-Erkennung fand eine Benachrichtigungs-Mail,
die stundenlang in einer Postfix-Warteschlange hing, weil der Provider den Absender
`root@<host>.fritz.box` ablehnte.
