#!/usr/bin/env bash
# Postfix als Homelab-Mail-Relay: nimmt Mails aus dem LAN an, schreibt den Absender
# auf <host>@provinglab.de um und liefert per SASL/STARTTLS bei SMTP2GO ab.
# Als root im Relay-Container ausfuehren:  SMTP_USER=... SMTP_PASS=... ./setup-relay.sh
set -euo pipefail

: "${SMTP_USER:?SMTP_USER fehlt}"
: "${SMTP_PASS:?SMTP_PASS fehlt}"
RELAYHOST="[mail-eu.smtp2go.com]:587"
DOMAIN="provinglab.de"
LAN="192.168.178.0/24"
DEST="${DEST:?DEST fehlt (Ziel-Postfach)}"   # wohin Mails an root/lokale Empfaenger gehen

cp -n /etc/postfix/main.cf /etc/postfix/main.cf.orig

# --- Zugangsdaten (nur root lesbar)
printf '%s %s:%s\n' "$RELAYHOST" "$SMTP_USER" "$SMTP_PASS" > /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd

# --- Absender umschreiben: alles auf @$DOMAIN, Host-Teil bleibt erhalten
#     root@pve.fritz.box -> pve@provinglab.de, wazuh@wazuh.fritz.box -> wazuh@provinglab.de
cat > /etc/postfix/sender_canonical.pcre <<EOF
# lokaler User auf einem Host: <user>@<host>[.domain] -> <host>@$DOMAIN
/^[^@]+@([a-z0-9-]+)(\.[a-z0-9.-]+)?$/   \${1}@$DOMAIN
EOF

# --- Empfaenger: root und lokale Adressen an das echte Postfach
cat > /etc/postfix/virtual <<EOF
root        $DEST
postmaster  $DEST
@$DOMAIN    $DEST
@relay      $DEST
EOF
postmap /etc/postfix/virtual

postconf -e \
  "myhostname = relay.$DOMAIN" \
  "myorigin = $DOMAIN" \
  "mydestination = " \
  "relayhost = $RELAYHOST" \
  "mynetworks = 127.0.0.0/8, [::1]/128, $LAN" \
  "inet_interfaces = all" \
  "inet_protocols = ipv4" \
  "smtpd_relay_restrictions = permit_mynetworks, reject" \
  "smtpd_recipient_restrictions = permit_mynetworks, reject" \
  "smtp_sasl_auth_enable = yes" \
  "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" \
  "smtp_sasl_security_options = noanonymous" \
  "smtp_sasl_tls_security_options = noanonymous" \
  "smtp_tls_security_level = encrypt" \
  "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt" \
  "smtp_tls_loglevel = 1" \
  "sender_canonical_maps = pcre:/etc/postfix/sender_canonical.pcre" \
  "sender_canonical_classes = envelope_sender, header_sender" \
  "virtual_alias_maps = hash:/etc/postfix/virtual" \
  "message_size_limit = 20480000" \
  "compatibility_level = 3.6"

apt-get install -y -q postfix-pcre > /dev/null
systemctl restart postfix
postfix check && echo "Postfix-Konfiguration ok"
echo "Testmail an $DEST ..."
echo "Testmail vom Homelab-Relay $(hostname) um $(date)" | mail -s "relay test" root
sleep 5
mailq | tail -n 1
journalctl -u postfix --since "1 min ago" --no-pager | grep -E 'status=|error|warning' | tail -n 5
