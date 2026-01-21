#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-ragoona.com}"
MAIL_API_HOSTNAME="${MAIL_API_HOSTNAME:-api.ragoona.com}"
TUNNEL_NAME="${TUNNEL_NAME:-ragoona-mail-api}"
LOCAL_API_URL="${LOCAL_API_URL:-http://127.0.0.1:8091}"

CF_API_TOKEN="${CF_API_TOKEN:-}"

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "run as root"
  fi
}

need_token() {
  if [[ -z "$CF_API_TOKEN" ]]; then
    die "set CF_API_TOKEN in environment (do not hardcode into files)"
  fi
}

install_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    return 0
  fi
  local deb="/tmp/cloudflared.deb"
  wget -O "$deb" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
  dpkg -i "$deb" >/dev/null 2>&1 || (apt-get update -y && apt-get install -y -f)
}

cf_api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  python3 - "$method" "$path" "$data" <<'PY'
import json, os, sys, urllib.request

method, path, data = sys.argv[1], sys.argv[2], sys.argv[3]
url = "https://api.cloudflare.com/client/v4" + path
headers = {
  "Authorization": "Bearer " + os.environ["CF_API_TOKEN"],
  "Content-Type": "application/json",
}
req = urllib.request.Request(url, method=method, headers=headers)
if data and data != "":  # data is JSON string
  req.data = data.encode("utf-8")
with urllib.request.urlopen(req, timeout=30) as r:
  body = r.read().decode("utf-8")
print(body)
PY
}

pick_account_id() {
  local json
  json="$(cf_api GET "/zones?name=${DOMAIN}" "")"
  python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
res=obj.get("result") or []
if not res:
  raise SystemExit(2)
acct=res[0].get("account") or {}
print(acct.get("id") or "")
PY
}

get_zone_id() {
  local json
  json="$(cf_api GET "/zones?name=${DOMAIN}" "")"
  python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
res=obj.get("result") or []
if not res:
  raise SystemExit(2)
print(res[0]["id"])
PY
}

gen_secret() {
  python3 - <<'PY'
import base64, os
print(base64.b64encode(os.urandom(32)).decode("ascii"))
PY
}

create_tunnel() {
  local account_id="$1"
  local secret="$2"
  local payload
  payload="$(python3 - <<PY
import json
print(json.dumps({"name":"$TUNNEL_NAME","tunnel_secret":"$secret"}, separators=(",",":")))
PY
)"
  local json
  json="$(cf_api POST "/accounts/${account_id}/cfd_tunnel" "$payload")"
  python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
print(obj["result"]["id"])
PY
}

get_tunnel_token() {
  local account_id="$1"
  local tunnel_id="$2"
  local json
  json="$(cf_api GET "/accounts/${account_id}/cfd_tunnel/${tunnel_id}/token" "")"
  python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
print(obj["result"])
PY
}

write_cloudflared_files() {
  local account_id="$1"
  local tunnel_id="$2"
  local secret="$3"

  install -d -m 0755 /etc/cloudflared

  local token_file="/etc/cloudflared/api.token"
  local token
  token="$(get_tunnel_token "$account_id" "$tunnel_id")"
  printf '%s\n' "$token" >"$token_file"
  chmod 0600 "$token_file"

  local cfg="/etc/cloudflared/api.yml"
  cat >"$cfg" <<EOF
ingress:
  - hostname: ${MAIL_API_HOSTNAME}
    service: ${LOCAL_API_URL}
  - service: http_status:404
EOF
  chmod 0644 "$cfg"

  local unit="/etc/systemd/system/cloudflared-api.service"
  cat >"$unit" <<EOF
[Unit]
Description=Cloudflare Tunnel for ${MAIL_API_HOSTNAME}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/cloudflared --protocol http2 --edge-ip-version 4 --retries 999999 --config ${cfg} tunnel run --token-file ${token_file}
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/cloudflared

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now cloudflared-api.service
}

create_dns_record() {
  local zone_id="$1"
  local tunnel_id="$2"
  local payload
  payload="$(python3 - <<PY
import json
print(json.dumps({"type":"CNAME","name":"$MAIL_API_HOSTNAME","content":"${tunnel_id}.cfargotunnel.com","proxied":True}, separators=(",",":")))
PY
)"
  cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null
}

main() {
  need_root
  need_token
  install_cloudflared

  local account_id zone_id secret tunnel_id
  account_id="$(pick_account_id)"
  zone_id="$(get_zone_id)"
  secret="$(gen_secret)"
  tunnel_id="$(create_tunnel "$account_id" "$secret")"

  create_dns_record "$zone_id" "$tunnel_id"
  write_cloudflared_files "$account_id" "$tunnel_id" "$secret"

  echo "tunnel_id=${tunnel_id}"
  echo "hostname=${MAIL_API_HOSTNAME}"
}

main "$@"

