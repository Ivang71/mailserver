#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-ragoona.com}"
MAIL_API_HOSTNAME="${MAIL_API_HOSTNAME:-api.ragoona.com}"
TUNNEL_NAME="${TUNNEL_NAME:-ragoona-mail-api}"
LOCAL_API_URL="${LOCAL_API_URL:-http://127.0.0.1:8091}"
MODE="${MODE:-auto}"
PUBLIC_IP="${PUBLIC_IP:-}"

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
  if command -v apt-get >/dev/null 2>&1; then
    local deb="/tmp/cloudflared.deb"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb" -o "$deb"
    else
      command -v wget >/dev/null 2>&1 || (apt-get update -y && apt-get install -y wget)
      wget -qO "$deb" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
    fi
    dpkg -i "$deb" >/dev/null 2>&1 || (apt-get update -y && apt-get install -y -f)
    return 0
  fi
  die "cloudflared install supported only on apt-based systems (install cloudflared manually)"
}

cf_api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  python3 - "$method" "$path" "$data" <<'PY'
import os, sys, urllib.request, urllib.error

method, path, data = sys.argv[1], sys.argv[2], sys.argv[3]
url = "https://api.cloudflare.com/client/v4" + path
headers = {
  "Authorization": "Bearer " + os.environ["CF_API_TOKEN"],
  "Content-Type": "application/json",
}
req = urllib.request.Request(url, method=method, headers=headers)
if data and data != "":  # data is JSON string
  req.data = data.encode("utf-8")
try:
  with urllib.request.urlopen(req, timeout=30) as r:
    sys.stdout.write(r.read().decode("utf-8"))
except urllib.error.HTTPError as e:
  sys.stdout.write(e.read().decode("utf-8"))
  raise SystemExit(1)
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

detect_public_ip() {
  if [[ -n "${PUBLIC_IP}" ]]; then
    printf '%s\n' "${PUBLIC_IP}"
    return 0
  fi
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  [[ -n "$ip" ]] || die "set PUBLIC_IP (could not detect)"
  printf '%s\n' "$ip"
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

get_existing_tunnel_id() {
  local account_id="$1"
  local json
  json="$(cf_api GET "/accounts/${account_id}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false" "")"
  python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
res=obj.get("result") or []
print(res[0]["id"] if res else "")
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

dns_upsert() {
  local zone_id="$1"
  local type="$2"
  local name="$3"
  local content="$4"
  local proxied="$5"

  local record_id
  local json
  json="$(cf_api GET "/zones/${zone_id}/dns_records?type=${type}&name=${name}" "")"
  record_id="$(
    python3 - <<PY
import json
obj=json.loads("""$json""")
if not obj.get("success"):
  raise SystemExit(1)
res=obj.get("result") or []
print(res[0]["id"] if res else "")
PY
)"

  local payload
  payload="$(python3 - "$type" "$name" "$content" "$proxied" <<'PY'
import json, sys
t, n, c, p = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
prox = p.lower() == "true"
print(json.dumps({"type": t, "name": n, "content": c, "proxied": prox}, separators=(",",":")))
PY
)"
  if [[ -n "$record_id" ]]; then
    cf_api PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload" >/dev/null
  else
    cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null
  fi
}

install_caddy() {
  command -v caddy >/dev/null 2>&1 && return 0
  command -v apt-get >/dev/null 2>&1 || die "caddy install supported only on apt-based systems"
  apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y caddy >/dev/null
}

write_caddyfile() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
${MAIL_API_HOSTNAME} {
  reverse_proxy 127.0.0.1:8091
}
EOF
  if [[ -e /etc/caddy/Caddyfile ]] && ! cmp -s "$tmp" /etc/caddy/Caddyfile; then
    cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
  fi
  install -D -m 0644 "$tmp" /etc/caddy/Caddyfile
  rm -f "$tmp"
  systemctl enable --now caddy >/dev/null
  systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null
}

main() {
  need_root
  need_token
  install_cloudflared

  local account_id zone_id secret tunnel_id
  account_id="$(pick_account_id)"
  zone_id="$(get_zone_id)"
  if [[ "$MODE" == "auto" ]]; then
    if cf_api GET "/accounts/${account_id}/cfd_tunnel?per_page=1" "" >/dev/null 2>&1; then
      MODE="tunnel"
    else
      MODE="proxy"
    fi
  fi

  if [[ "$MODE" == "tunnel" ]]; then
    tunnel_id="$(get_existing_tunnel_id "$account_id")"
    if [[ -z "$tunnel_id" ]]; then
      secret="$(gen_secret)"
      tunnel_id="$(create_tunnel "$account_id" "$secret")"
    fi
    dns_upsert "$zone_id" "CNAME" "$MAIL_API_HOSTNAME" "${tunnel_id}.cfargotunnel.com" "true"
    write_cloudflared_files "$account_id" "$tunnel_id" "${secret:-unused}"
    echo "mode=tunnel"
    echo "tunnel_id=${tunnel_id}"
    echo "hostname=${MAIL_API_HOSTNAME}"
    return 0
  fi

  local ipaddr
  ipaddr="$(detect_public_ip)"
  dns_upsert "$zone_id" "A" "$MAIL_API_HOSTNAME" "$ipaddr" "true"
  install_caddy
  write_caddyfile
  echo "mode=proxy"
  echo "hostname=${MAIL_API_HOSTNAME}"
}

main "$@"

