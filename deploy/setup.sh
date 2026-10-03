#!/usr/bin/env bash
#
# Provision Wasabi on a fresh Debian/Ubuntu host.
#
#   DOMAIN=automint.wasabii.xyz EMAIL=you@example.com bash deploy/setup.sh
#
# Put the droplet in the sequencer's region. Robinhood Chain's sequencer is in
# AWS us-east-2 (Columbus, Ohio): a DigitalOcean NYC or TOR box sits ~20ms away,
# Singapore ~230ms. That distance is the whole reason to deploy at all.
#
# The app listens on loopback only. nginx terminates TLS and proxies to it --
# Python's http.server is not meant to face the internet directly.
set -euo pipefail

: "${DOMAIN:?set DOMAIN=automint.wasabii.xyz}"
: "${EMAIL:?set EMAIL=you@example.com for certbot}"
APP_DIR=${APP_DIR:-/opt/wasabi}

# A freshly registered domain can take up to an hour to appear at the registry,
# so provisioning is allowed to run ahead of DNS: SKIP_TLS=1 does everything
# except certbot, and the script can be re-run later to finish the job.
SKIP_TLS=${SKIP_TLS:-0}
echo "==> checking DNS"
if getent hosts "$DOMAIN" >/dev/null; then
  echo "    $DOMAIN resolves"
elif [ "$SKIP_TLS" = "1" ]; then
  echo "    $DOMAIN does not resolve yet — provisioning without TLS"
else
  echo "STOP: $DOMAIN does not resolve. Add the A record first, or re-run with" >&2
  echo "      SKIP_TLS=1 to provision now and issue the certificate later." >&2
  exit 1
fi

echo "==> packages"
apt-get update -qq
apt-get install -y -qq nginx certbot python3-certbot-nginx curl git ufw

echo "==> foundry (cast) for signing"
if ! command -v cast >/dev/null; then
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup
fi

echo "==> app"
mkdir -p "$APP_DIR/wallets"
chmod 700 "$APP_DIR/wallets"
[ -d "$APP_DIR/.git" ] || git clone -q https://github.com/belulok/wasabii.git "$APP_DIR"
git -C "$APP_DIR" pull -q || true

# A token is required; everything on this service can sign with whatever key
# material is on the host, so there is no unauthenticated mode.
if [ ! -f "$APP_DIR/.env" ]; then
  echo "WASABI_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)" > "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"
fi

echo "==> systemd"
cat > /etc/systemd/system/wasabi.service <<UNIT
[Unit]
Description=Wasabi mint console
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
Environment=BIND=127.0.0.1
Environment=PORT=8899
Environment=PATH=/root/.foundry/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/python3 $APP_DIR/server.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$APP_DIR

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wasabi

echo "==> nginx"
cat > /etc/nginx/sites-available/wasabi <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # filled in by certbot
    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    # the app signs transactions, so keep the blast radius small
    limit_req zone=wasabi burst=20 nodelay;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8899;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 120s;
    }
}
NGINX
grep -q 'limit_req_zone.*wasabi' /etc/nginx/nginx.conf || \
  sed -i '/http {/a \    limit_req_zone $binary_remote_addr zone=wasabi:10m rate=10r/s;' /etc/nginx/nginx.conf
ln -sf /etc/nginx/sites-available/wasabi /etc/nginx/sites-enabled/wasabi
rm -f /etc/nginx/sites-enabled/default

echo "==> certificate"
if [ "$SKIP_TLS" = "1" ] && ! getent hosts "$DOMAIN" >/dev/null; then
  # nginx will not start with ssl_certificate paths that do not exist yet
  sed -i '/listen 443 ssl/,$d' /etc/nginx/sites-available/wasabi
  printf '%s\n' 'server { listen 443 ssl http2; server_name '"$DOMAIN"'; return 503; }' \
    > /dev/null   # placeholder intentionally omitted; port 80 only until certbot runs
  sed -i 's#location / { return 301 https://\$host\$request_uri; }#location / { proxy_pass http://127.0.0.1:8899; proxy_set_header Host $host; }#' \
    /etc/nginx/sites-available/wasabi
  echo "    deferred — re-run this script without SKIP_TLS once DNS resolves"
else
  certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos \
    -m "$EMAIL" --redirect || \
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
fi
nginx -t && systemctl reload nginx

echo "==> firewall"
ufw allow OpenSSH >/dev/null; ufw allow 'Nginx Full' >/dev/null
ufw --force enable >/dev/null

echo
echo "done.  https://$DOMAIN/?token=$(grep WASABI_TOKEN "$APP_DIR/.env" | cut -d= -f2)"
echo
echo "NOTE: issuing the certificate publishes $DOMAIN to Certificate Transparency"
echo "      logs, so scanners will find it within hours. The token is the only"
echo "      thing between the internet and a service that signs transactions."
echo "      Upload wallet files to $APP_DIR/wallets (chmod 600) and nowhere else."
