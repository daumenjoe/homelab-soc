# MISP (Threat-Intel-Speicher)

Offizielles `misp-docker` (github.com/MISP/misp-docker) auf einer eigenen VM (4 vCPU, 8 GB, Ubuntu).
Wesentliche `.env`-Werte, alle vor dem ersten Start setzen (BASE_URL und Admin werden in die DB gebrannt):

    CORE_RUNNING_TAG=${CORE_TAG}   MODULES_RUNNING_TAG=${MODULES_TAG}   GUARD_RUNNING_TAG=${GUARD_TAG}   # sonst :latest
    BASE_URL=https://misp.<domain>  ADMIN_EMAIL=...  ADMIN_ORG=...  ADMIN_PASSWORD=<zufall>  GPG_PASSPHRASE=<zufall>
    MYSQL_PASSWORD=<zufall>  MYSQL_ROOT_PASSWORD=<zufall>
    SMARTHOST_ADDRESS=<mail-relay>  SMARTHOST_PORT=25
    FETCH_FEED_INTERVAL=6h  CACHE_FEED_INTERVAL=1h

Stolperfallen: Der Healthcheck von `misp-core` läuft beim Erstlauf ab, bevor die DB-Initialisierung fertig
ist – warten, bis `healthy`, dann `docker compose up -d` erneut. Bei `BASE_URL` mit https braucht nginx
`./ssl/cert.pem` und `./ssl/key.pem`; der Ordner entsteht als root, `key.pem` muss für den Container-nginx
lesbar sein (644). Zertifikat kommt vom Relay (`deploy-cert.sh`, acme.sh, DNS-01).

Feeds (Kern): CIRCL OSINT, abuse.ch URLhaus / ThreatFox / Feodo Tracker, Botvrij.eu, OpenPhish.
Anbindung: Auth-Key für `custom-iris` (Abfrage `/attributes/restSearch` für Domain und Client-IP) – siehe integrations/.
