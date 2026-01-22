#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-ragoona.com}"
MX_HOSTNAME="${MX_HOSTNAME:-${DOMAIN}}"
MX_PRIORITY="${MX_PRIORITY:-10}"
PUBLIC_IP="${PUBLIC_IP:-}"

CF_API_TOKEN="${CF_API_TOKEN:-}"

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "run as root"
  fi
}

need_token() {
  [[ -n "$CF_API_TOKEN" ]] || die "set CF_API_TOKEN in environment"
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
if data and data != "":
  req.data = data.encode("utf-8")
try:
  with urllib.request.urlopen(req, timeout=30) as r:
    sys.stdout.write(r.read().decode("utf-8"))
except urllib.error.HTTPError as e:
  sys.stdout.write(e.read().decode("utf-8"))
  raise SystemExit(1)
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

dns_upsert() {
  local zone_id="$1"
  local payload="$2"
  local type name
  type="$(python3 - <<PY
import json
print(json.loads("""$payload""")["type"])
PY
)"
  name="$(python3 - <<PY
import json
print(json.loads("""$payload""")["name"])
PY
)"

  local record_id json
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
  if [[ -n "$record_id" ]]; then
    cf_api PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload" >/dev/null
  else
    cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null
  fi
}

main() {
  need_root
  need_token

  local zone_id ip
  zone_id="$(get_zone_id)"
  ip="$(detect_public_ip)"

  local a_payload mx_payload
  a_payload="$(python3 - <<PY
import json
print(json.dumps({"type":"A","name":"$MX_HOSTNAME","content":"$ip","proxied":False}, separators=(",",":")))
PY
)"
  mx_payload="$(python3 - <<PY
import json
print(json.dumps({"type":"MX","name":"$DOMAIN","content":"$MX_HOSTNAME","priority":int("$MX_PRIORITY")}, separators=(",",":")))
PY
)"
  dns_upsert "$zone_id" "$a_payload"
  dns_upsert "$zone_id" "$mx_payload"
  echo "domain=${DOMAIN}"
  echo "mx_hostname=${MX_HOSTNAME}"
  echo "public_ip=${ip}"
}

main "$@"

