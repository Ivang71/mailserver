#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${DB_PATH:-/opt/farm/worker_farm.db}"
EMAIL_ID="${1:-}"
OUT_PATH="${2:-}"

if [[ -z "$EMAIL_ID" ]]; then
  EMAIL_ID="$(
    python3 - "$DB_PATH" <<'PY'
import sqlite3,sys
db=sys.argv[1]
con=sqlite3.connect(db)
cur=con.cursor()
row=cur.execute(
    "select id from raw_emails where cast(raw as text) like '%text/html%' order by id desc limit 1"
).fetchone()
if not row:
    row=cur.execute("select id from raw_emails order by id desc limit 1").fetchone()
con.close()
print(row[0] if row else "")
PY
  )"
fi

[[ -n "$EMAIL_ID" ]] || { echo "no raw_emails found in ${DB_PATH}" >&2; exit 1; }

if [[ -z "$OUT_PATH" ]]; then
  OUT_PATH="raw-email-${EMAIL_ID}.html"
fi

python3 - "$DB_PATH" "$EMAIL_ID" "$OUT_PATH" <<'PY'
import sqlite3,sys
from email import message_from_bytes

db=sys.argv[1]
rid=int(sys.argv[2])
out=sys.argv[3]

con=sqlite3.connect(db)
cur=con.cursor()
row=cur.execute("select raw from raw_emails where id=?", (rid,)).fetchone()
con.close()
if not row:
    raise SystemExit(f"email id not found: {rid}")

raw=row[0] or b""
msg=message_from_bytes(raw)

html=None
def decode(part):
    payload = part.get_payload(decode=True) or b""
    cs = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(cs, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")

if msg.is_multipart():
    for p in msg.walk():
        if p.get_content_type() == "text/html":
            html = decode(p)
            break
else:
    if msg.get_content_type() == "text/html":
        html = decode(msg)

if html is None:
    raise SystemExit(f"email id has no text/html part: {rid}")

with open(out, "w", encoding="utf-8") as f:
    f.write(html)

print(out)
PY
