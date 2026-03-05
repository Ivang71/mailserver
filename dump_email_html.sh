#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${DB_PATH:-/opt/farm/worker_farm.db}"
OUT_DIR="${1:-raw-email-dump}"

mkdir -p "$OUT_DIR"

python3 - "$DB_PATH" "$OUT_DIR" <<'PY'
import os, sqlite3, sys
from email import message_from_bytes

db=sys.argv[1]
out_dir=sys.argv[2]

def decode(part):
    payload = part.get_payload(decode=True) or b""
    cs = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(cs, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")

def extract_html(raw):
    msg = message_from_bytes(raw)
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/html":
                return decode(p)
        return None
    if msg.get_content_type() == "text/html":
        return decode(msg)
    return None

con=sqlite3.connect(db)
cur=con.cursor()
rows=cur.execute("select id,created_at,raw from raw_emails order by id asc").fetchall()
con.close()

if not rows:
    raise SystemExit(f"no raw_emails found in {db}")

written_eml=0
written_html=0

for rid, created_at, raw in rows:
    raw = raw or b""
    base = f"{rid}"
    eml_path = os.path.join(out_dir, f"raw-{base}.eml")
    with open(eml_path, "wb") as f:
        f.write(raw)
    written_eml += 1

    html = extract_html(raw)
    if html is not None:
        html_path = os.path.join(out_dir, f"raw-{base}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        written_html += 1

print(f"dumped={len(rows)} eml={written_eml} html={written_html} dir={out_dir}")
PY
