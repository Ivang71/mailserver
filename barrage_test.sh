#!/usr/bin/env bash
set -euo pipefail

N="${N:-30}"
SMTP_HOST="${SMTP_HOST:-127.0.0.1}"
SMTP_PORT="${SMTP_PORT:-25}"
TO_DOMAIN="${TO_DOMAIN:-ragoona.com}"
LOCAL_API="${LOCAL_API:-http://127.0.0.1:8091}"
CLOUDFLARE_API="${CLOUDFLARE_API:-https://api.ragoona.com}"

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "need $1"; }

need python3

send_mail_barrage() {
  python3 - "$N" "$SMTP_HOST" "$SMTP_PORT" "$TO_DOMAIN" <<'PY'
import smtplib, sys, time
from email.message import EmailMessage

n=int(sys.argv[1])
host=sys.argv[2]
port=int(sys.argv[3])
dom=sys.argv[4]

s=smtplib.SMTP(host, port, timeout=10)
for i in range(n):
  msg=EmailMessage()
  msg["From"]="tester@%s" % dom
  msg["To"]="user%05d@%s" % (i, dom)
  msg["Subject"]="cf verify %05d" % i
  msg.set_content("hi")
  token="tok_%d_%d" % (int(time.time()), i)
  msg.add_alternative('x <a href="https://dash.cloudflare.com/verify-email?token=%s">v</a>' % token, subtype="html")
  s.send_message(msg)
s.quit()
PY
}

api_get_unread_count() {
  python3 - "$1" <<'PY'
import json, sys, urllib.request
url=sys.argv[1].rstrip("/") + "/unread"
with urllib.request.urlopen(url, timeout=10) as r:
  body=r.read().decode("utf-8")
obj=json.loads(body)
print(len(obj))
PY
}

api_read_one() {
  python3 - "$1" <<'PY'
import json, sys, urllib.request
base=sys.argv[1].rstrip("/")
with urllib.request.urlopen(base + "/unread", timeout=10) as r:
  obj=json.loads(r.read().decode("utf-8"))
if not obj:
  raise SystemExit(2)
rid=obj[0]["id"]
req=urllib.request.Request(
  base + "/read",
  data=json.dumps({"id":rid}).encode("utf-8"),
  headers={"Content-Type":"application/json"},
  method="POST",
)
with urllib.request.urlopen(req, timeout=10) as r:
  out=json.loads(r.read().decode("utf-8"))
if not out.get("deleted"):
  raise SystemExit(3)
print(rid)
PY
}

main() {
  echo "smtp_barrage=${N} to ${SMTP_HOST}:${SMTP_PORT} *@${TO_DOMAIN}"
  send_mail_barrage
  sleep 0.8

  echo "local_api=${LOCAL_API}"
  local c
  c="$(api_get_unread_count "$LOCAL_API")"
  echo "local_unread=${c}"
  [[ "$c" -gt 0 ]] || die "local unread is 0"
  api_read_one "$LOCAL_API" >/dev/null

  echo "cloudflare_api=${CLOUDFLARE_API}"
  c="$(api_get_unread_count "$CLOUDFLARE_API")"
  echo "cloudflare_unread=${c}"
  [[ "$c" -gt 0 ]] || die "cloudflare unread is 0"
  api_read_one "$CLOUDFLARE_API" >/dev/null

  echo "ok"
}

main "$@"
