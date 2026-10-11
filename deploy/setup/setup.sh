#!/bin/sh
# One-time setup of the laboratory: every secret, key and certificate SecureDesk needs.
#
#   docker compose run --rm setup
#
# Writes ./secrets/ (git-ignored). Nothing is overwritten on a later run, so the keys that
# protect stored passwords and TOTP secrets never change by accident. Each service gets a
# directory of its own and mounts only that one (SR-06: least privilege for secrets too):
#
#   secrets/ca/         the internal CA; its key is never mounted into any container
#   secrets/api/        DB password, pepper and TOTP keys, bootstrap passwords, API TLS
#   secrets/migrate/    the migrator's DB password and the CA trust store
#   secrets/mysql/      root, migrator and app passwords, MySQL TLS
#   secrets/nginx/      the public certificate and Nginx's client certificate for the API
#   secrets/collector/  the collector's TLS
#   secrets/mail/       the mail relay's TLS
#
# In the reference architecture these files are rendered by the secrets vault of the
# management zone; key management is BoK 6.5.
#
# POSIX sh on purpose: it runs in the API's own base image (OpenSSL and keytool included), so
# the setup needs nothing downloaded.
set -eu
umask 077

OUT=/work/secrets
HOSTNAME_PUBLIC="${SECUREDESK_HOSTNAME:-securedesk.localhost}"
DAYS_CA=730
DAYS_LEAF=365
CREATED=0

mkdir -p "$OUT/ca/issued" "$OUT/api/config" "$OUT/api/tls" "$OUT/migrate/config" "$OUT/migrate/tls" \
         "$OUT/mysql/tls" "$OUT/nginx/tls" "$OUT/collector/tls" "$OUT/mail/tls"

# write FILE VALUE: creates a secret file once, never overwrites one
write() {
    if [ ! -s "$1" ]; then
        printf '%s' "$2" > "$1"
        CREATED=$((CREATED + 1))
    fi
}

# read_or FILE GENERATED: the existing value of a secret, or a new one
read_or() {
    if [ -s "$1" ]; then cat "$1"; else printf '%s' "$2"; fi
}

random_hex() { openssl rand -hex "$1"; }
random_key() { openssl rand -base64 32; }
# Four groups of five from an alphabet without look-alikes, as the API's temporary passwords.
random_password() {
    LC_ALL=C tr -dc 'abcdefghjkmnpqrstuvwxyz23456789' < /dev/urandom | head -c 20 \
        | sed 's/\(.....\)\(.....\)\(.....\)\(.....\)/\1-\2-\3-\4/'
}

# ---- passwords and keys -----------------------------------------------------------------------

db_root="$(read_or "$OUT/mysql/root-password" "$(random_hex 24)")"
db_app="$(read_or "$OUT/mysql/app-password" "$(random_hex 24)")"
db_migrator="$(read_or "$OUT/mysql/migrator-password" "$(random_hex 24)")"
write "$OUT/mysql/root-password" "$db_root"
write "$OUT/mysql/app-password" "$db_app"
write "$OUT/mysql/migrator-password" "$db_migrator"
write "$OUT/api/config/securedesk.db.password" "$db_app"
write "$OUT/migrate/config/db-password" "$db_migrator"

# The pepper and the TOTP column key: 32 random bytes each, key id k1 (BoK 6.3, SR-05).
write "$OUT/api/config/securedesk.crypto.pepper.keys.k1" "$(random_key)"
write "$OUT/api/config/securedesk.crypto.totp.keys.k1" "$(random_key)"

admin_password="$(read_or "$OUT/api/config/securedesk.bootstrap.admin-password" "$(random_password)")"
demo_password="$(read_or "$OUT/api/config/securedesk.demo.password" "$(random_password)")"
write "$OUT/api/config/securedesk.bootstrap.admin-password" "$admin_password"
write "$OUT/api/config/securedesk.demo.password" "$demo_password"

# ---- the internal CA --------------------------------------------------------------------------

if [ ! -s "$OUT/ca/ca.key" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/ca/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$OUT/ca/ca.key" -sha256 -days "$DAYS_CA" \
        -subj "/O=SecureDesk laboratory/CN=SecureDesk Internal CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$OUT/ca/ca.crt"
    CREATED=$((CREATED + 2))
fi

# leaf NAME COMMON_NAME SUBJECT_ALT_NAMES EXTENDED_KEY_USAGE: an EC P-256 key and a certificate
leaf() {
    name="$1"; cn="$2"; san="$3"; eku="$4"; dir="$OUT/ca/issued"
    if [ -s "$dir/$name.crt" ]; then
        return
    fi
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$name.key" 2>/dev/null
    openssl req -new -key "$dir/$name.key" -subj "/O=SecureDesk laboratory/CN=$cn" -out "$dir/$name.csr"
    cat > "$dir/$name.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$eku
subjectAltName=$san
EXT
    openssl x509 -req -in "$dir/$name.csr" -CA "$OUT/ca/ca.crt" -CAkey "$OUT/ca/ca.key" -CAcreateserial \
        -days "$DAYS_LEAF" -sha256 -extfile "$dir/$name.ext" -out "$dir/$name.crt" 2>/dev/null
    rm -f "$dir/$name.csr" "$dir/$name.ext"
    CREATED=$((CREATED + 1))
}

# Every hop is TLS (SR-04): browser -> Nginx -> API -> MySQL, API -> collector, API -> mail.
leaf nginx        "$HOSTNAME_PUBLIC" "DNS:$HOSTNAME_PUBLIC,DNS:localhost,IP:127.0.0.1" "serverAuth"
leaf nginx-client "securedesk-nginx" "DNS:securedesk-nginx"                         "clientAuth"
leaf api          "api"              "DNS:api"                                      "serverAuth"
leaf api-syslog   "securedesk-api"   "DNS:securedesk-api"                           "clientAuth"
leaf mysql        "mysql"            "DNS:mysql"                                    "serverAuth"
leaf collector    "collector"        "DNS:collector"                                "serverAuth"
leaf mail         "mail"             "DNS:mail"                                     "serverAuth"

# A PKCS#12 trust store holding only the internal CA, for the JVM (MySQL and the mail relay).
# Its password protects nothing secret; Java simply wants one.
if [ ! -s "$OUT/ca/truststore.p12" ]; then
    keytool -importcert -noprompt -alias securedesk-internal-ca -file "$OUT/ca/ca.crt" \
        -keystore "$OUT/ca/truststore.p12" -storetype PKCS12 -storepass changeit > /dev/null
    CREATED=$((CREATED + 1))
fi

# ---- hand each service its own files ---------------------------------------------------------

issued="$OUT/ca/issued"

cp "$OUT/ca/ca.crt"          "$OUT/api/tls/ca.crt"
cp "$OUT/ca/truststore.p12"  "$OUT/api/tls/truststore.p12"
cp "$issued/api.crt"         "$OUT/api/tls/api.crt"
cp "$issued/api.key"         "$OUT/api/tls/api.key"
cp "$issued/api-syslog.crt"  "$OUT/api/tls/api-syslog.crt"
cp "$issued/api-syslog.key"  "$OUT/api/tls/api-syslog.key"

cp "$OUT/ca/truststore.p12"  "$OUT/migrate/tls/truststore.p12"

cp "$OUT/ca/ca.crt"          "$OUT/mysql/tls/ca.crt"
cp "$issued/mysql.crt"       "$OUT/mysql/tls/mysql.crt"
cp "$issued/mysql.key"       "$OUT/mysql/tls/mysql.key"

cp "$OUT/ca/ca.crt"          "$OUT/nginx/tls/ca.crt"
cat "$issued/nginx.crt" "$OUT/ca/ca.crt" > "$OUT/nginx/tls/server.crt"
cp "$issued/nginx.key"       "$OUT/nginx/tls/server.key"
cp "$issued/nginx-client.crt" "$OUT/nginx/tls/client.crt"
cp "$issued/nginx-client.key" "$OUT/nginx/tls/client.key"

cp "$OUT/ca/ca.crt"          "$OUT/collector/tls/ca.crt"
cp "$issued/collector.crt"   "$OUT/collector/tls/collector.crt"
cp "$issued/collector.key"   "$OUT/collector/tls/collector.key"

cp "$issued/mail.crt"        "$OUT/mail/tls/mail.crt"
cp "$issued/mail.key"        "$OUT/mail/tls/mail.key"

# The containers run as different unprivileged users (mysql, nginx, the API's uid 10001, the
# collector), so the files of a service's directory must be readable to them. The top-level
# directory stays private on the host; the CA's key is readable by its owner only.
find "$OUT" -mindepth 1 -type d -exec chmod 755 {} +
find "$OUT" -mindepth 1 -type f -exec chmod 644 {} +
chmod 700 "$OUT" "$OUT/ca"
chmod 600 "$OUT/ca/ca.key"

cat > "$OUT/README.txt" <<EOF
Generated by deploy/setup/setup.sh. Never commit this directory.

Sign in at https://$HOSTNAME_PUBLIC:8443 after 'docker compose up -d --build'.
Import ca/ca.crt into your browser or operating system to trust the laboratory certificates.

First administrator: admin
  password: api/config/securedesk.bootstrap.admin-password (replace it at the first sign-in)
Demonstration accounts (requesters alice and bob, agents carol and dave):
  password: api/config/securedesk.demo.password
EOF

echo "SecureDesk setup"
if [ "$CREATED" -eq 0 ]; then
    echo "  Nothing new: every secret already exists and was left unchanged."
else
    echo "  Created $CREATED secret(s) or certificate(s) under ./secrets (git-ignored)."
fi
echo
echo "  First administrator:    admin / $admin_password   (replace it at the first sign-in)"
echo "  Demonstration accounts: alice, bob (requesters), carol, dave (agents) / $demo_password"
echo
echo "  Trust ./secrets/ca/ca.crt in your browser, then open https://$HOSTNAME_PUBLIC:8443"
