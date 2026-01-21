#!/usr/bin/env bash
set -euo pipefail

MADDY_VERSION="${MADDY_VERSION:-0.7.1}"
PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-ragoona.com}"
MX_HOSTNAME="${MX_HOSTNAME:-mx1.ragoona.com}"

MADDY_BIN="/usr/local/bin/maddy"
MADDY_CONF_DIR="/etc/maddy"
MADDY_CONF="${MADDY_CONF_DIR}/maddy.conf"

FARM_DIR="/opt/farm"
PARSER="${FARM_DIR}/parse_email.py"
SINK="${FARM_DIR}/smtp_sink.py"
API="${FARM_DIR}/mail_api.py"
DB="${FARM_DIR}/worker_farm.db"
API_PORT="${API_PORT:-8091}"

FW_HELPER="/usr/local/sbin/mail-allow-smtp25"
FW_UNIT="/etc/systemd/system/mail-allow-smtp25.service"
MADDY_UNIT="/etc/systemd/system/maddy.service"
SINK_UNIT="/etc/systemd/system/farm-smtp-sink.service"
API_UNIT="/etc/systemd/system/farm-mail-api.service"

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "run as root"
  fi
}

write_managed_file() {
  local path="$1"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -e "$path" ]]; then
    if ! cmp -s "$tmp" "$path"; then
      cp -a "$path" "${path}.bak.$(date +%s)"
      install -m 0644 "$tmp" "$path"
    fi
    rm -f "$tmp"
    return 0
  fi
  install -D -m 0644 "$tmp" "$path"
  rm -f "$tmp"
}

install_maddy() {
  if [[ -x "$MADDY_BIN" ]]; then
    return 0
  fi
  if ! command -v zstd >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y zstd
  fi
  local tarzst="/tmp/maddy-${MADDY_VERSION}.tar.zst"
  wget -O "$tarzst" "https://github.com/foxcpp/maddy/releases/download/v${MADDY_VERSION}/maddy-${MADDY_VERSION}-x86_64-linux-musl.tar.zst"
  rm -rf "/tmp/maddy-${MADDY_VERSION}-x86_64-linux-musl"
  tar --zstd -xf "$tarzst" -C /tmp
  install -m 0755 "/tmp/maddy-${MADDY_VERSION}-x86_64-linux-musl/maddy" "$MADDY_BIN"
}

install_deps() {
  if python3 -c "import aiosmtpd" >/dev/null 2>&1; then
    return 0
  fi
  apt-get update -y
  apt-get install -y python3-aiosmtpd
}

ensure_user() {
  if id -u maddy >/dev/null 2>&1; then
    return 0
  fi
  useradd --system --home /var/lib/maddy --shell /usr/sbin/nologin maddy
}

ensure_farm_user() {
  getent group farm >/dev/null 2>&1 || groupadd --system farm
  if ! id -u farmapi >/dev/null 2>&1; then
    useradd --system --home /nonexistent --shell /usr/sbin/nologin -g farm farmapi
  fi
}

write_configs() {
  install -d -m 0755 "$MADDY_CONF_DIR"
  install -d -m 0755 "/etc/maddy/certs/${MX_HOSTNAME}"

  if [[ ! -e "/etc/maddy/certs/${MX_HOSTNAME}/fullchain.pem" || ! -e "/etc/maddy/certs/${MX_HOSTNAME}/privkey.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "/etc/maddy/certs/${MX_HOSTNAME}/privkey.pem" \
      -out "/etc/maddy/certs/${MX_HOSTNAME}/fullchain.pem" \
      -days 3650 -subj "/CN=${MX_HOSTNAME}" >/dev/null 2>&1
    chown root:maddy "/etc/maddy/certs/${MX_HOSTNAME}/privkey.pem"
    chmod 0640 "/etc/maddy/certs/${MX_HOSTNAME}/privkey.pem"
    chmod 0644 "/etc/maddy/certs/${MX_HOSTNAME}/fullchain.pem"
  fi

  write_managed_file "$MADDY_CONF" <<EOF
\$(hostname) = ${MX_HOSTNAME}
\$(primary_domain) = ${PRIMARY_DOMAIN}
\$(local_domains) = \$(primary_domain)

tls file /etc/maddy/certs/\$(hostname)/fullchain.pem /etc/maddy/certs/\$(hostname)/privkey.pem

state_dir /var/lib/maddy
runtime_dir /run/maddy

hostname \$(hostname)

msgpipeline local_routing {
    destination \$(local_domains) {
        deliver_to smtp tcp://127.0.0.1:2525
    }

    default_destination {
        reject 550 5.1.1 "User not found"
    }
}

smtp tcp://0.0.0.0:25 {
    limits {
        all rate 20 1s
    }
    default_source {
        destination \$(local_domains) { deliver_to &local_routing }
        default_destination { reject 550 5.1.1 "User not found" }
    }
}
EOF

  write_managed_file "$FW_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v nft >/dev/null 2>&1; then
  exit 0
fi

if nft list chain inet eus_firewall input 2>/dev/null | grep -qE 'tcp dport 25 accept'; then
  exit 0
fi

nft add rule inet eus_firewall input tcp dport 25 accept
EOF
  chmod 0755 "$FW_HELPER"

  write_managed_file "$FW_UNIT" <<EOF
[Unit]
Description=Allow inbound SMTP on tcp/25 in nftables (eus_firewall)
After=nftables.service
Wants=nftables.service

[Service]
Type=oneshot
ExecStart=${FW_HELPER}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  write_managed_file "$MADDY_UNIT" <<EOF
[Unit]
Description=Maddy Mail Server (Inbound Pipe)
After=network-online.target mail-allow-smtp25.service farm-smtp-sink.service
Wants=network-online.target mail-allow-smtp25.service farm-smtp-sink.service

[Service]
User=maddy
Group=maddy
ExecStart=${MADDY_BIN} --config ${MADDY_CONF} run
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/maddy /run/maddy ${FARM_DIR}
RuntimeDirectory=maddy
StateDirectory=maddy

[Install]
WantedBy=multi-user.target
EOF

  write_managed_file "$SINK_UNIT" <<EOF
[Unit]
Description=Local SMTP sink that pipes messages into /opt/farm/parse_email.py
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/bin/python3 ${SINK}
Restart=on-failure
RestartSec=1s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${FARM_DIR}

[Install]
WantedBy=multi-user.target
EOF

  write_managed_file "$API_UNIT" <<EOF
[Unit]
Description=Local mail API for /opt/farm/worker_farm.db
After=network.target

[Service]
User=farmapi
Group=farm
ExecStart=/usr/bin/python3 ${API} --bind 127.0.0.1 --port ${API_PORT}
Restart=on-failure
RestartSec=1s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${FARM_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

write_parser_and_db() {
  install -d -m 0755 "$FARM_DIR"

  write_managed_file "$PARSER" <<'EOF'
import re
import sqlite3
import sys
from email import message_from_bytes
from email.utils import getaddresses

raw = sys.stdin.buffer.read()
msg = message_from_bytes(raw)

body = ""
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")
            break
else:
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    body = payload.decode(charset, errors="replace")

m = re.search(r"https://dash\.cloudflare\.com/verify-email\?token=[a-zA-Z0-9._-]+", body)
if not m:
    sys.exit(0)

to_hdr = msg.get_all("to", [])
addr = getaddresses(to_hdr)
recipient = addr[0][1] if addr else ""
link = m.group(0)

conn = sqlite3.connect("/opt/farm/worker_farm.db", timeout=10)
cur = conn.cursor()
cur.execute(
    "CREATE TABLE IF NOT EXISTS verification_links (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, link TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
)
cur.execute(
    "INSERT INTO verification_links (email, link, status) VALUES (?, ?, 'pending')",
    (recipient, link),
)
conn.commit()
conn.close()
EOF
  chmod 0755 "$PARSER"

  write_managed_file "$SINK" <<'EOF'
import asyncio
import subprocess

from aiosmtpd.controller import Controller


class Handler:
    async def handle_DATA(self, server, session, envelope):
        data = envelope.original_content if hasattr(envelope, "original_content") else envelope.content
        try:
            subprocess.run(
                ["/usr/bin/python3", "/opt/farm/parse_email.py"],
                input=data,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            return "451 Requested action aborted: local error in processing"
        return "250 OK"


def main():
    controller = Controller(Handler(), hostname="127.0.0.1", port=2525)
    controller.start()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_forever()
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
EOF
  chmod 0755 "$SINK"

  write_managed_file "$API" <<'EOF'
import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DB_PATH = "/opt/farm/worker_farm.db"


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if obj is not None:
            self.wfile.write(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def do_GET(self):
        if self.path != "/unread":
            self._json(404, {"error": "not_found"})
            return

        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            cur = conn.cursor()
            cur.execute(
                "select id,email,link,created_at from verification_links where status='pending' order by id asc limit 1"
            )
            row = cur.fetchone()
        finally:
            conn.close()

        if not row:
            self.send_response(204)
            self.end_headers()
            return

        self._json(
            200,
            {"id": row[0], "email": row[1], "link": row[2], "created_at": row[3]},
        )

    def do_POST(self):
        if self.path != "/read":
            self._json(404, {"error": "not_found"})
            return

        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self._json(400, {"error": "bad_request"})
            return

        try:
            body = self.rfile.read(length) if length else b"{}"
            data = json.loads(body.decode("utf-8"))
            rid = int(data.get("id"))
        except Exception:
            self._json(400, {"error": "bad_request"})
            return

        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            try:
                cur = conn.cursor()
                cur.execute("delete from verification_links where id=? and status='pending'", (rid,))
                deleted = cur.rowcount
                conn.commit()
            finally:
                conn.close()
        except sqlite3.OperationalError:
            self._json(500, {"error": "db_error"})
            return

        if deleted:
            self._json(200, {"deleted": True})
        else:
            self._json(404, {"deleted": False})

    def log_message(self, fmt, *args):
        return


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8091)
    args = p.parse_args()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
EOF
  chmod 0755 "$API"

  python3 - <<EOF
import sqlite3
conn = sqlite3.connect("${DB}", timeout=10)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS verification_links (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, link TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
conn.commit()
conn.close()
EOF

  chown -R root:farm "$FARM_DIR"
  chmod 0770 "$FARM_DIR"
  chmod 0750 "$PARSER" "$SINK" "$API"
  chmod 0660 "$DB" || true
}

start_services() {
  systemctl daemon-reload
  systemctl enable --now mail-allow-smtp25.service
  systemctl enable --now farm-smtp-sink.service
  systemctl enable --now farm-mail-api.service
  systemctl reset-failed maddy.service 2>/dev/null || true
  systemctl enable --now maddy.service
}

do_test() {
  python3 - <<'EOF'
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "tester@ragoona.com"
msg["To"] = "user999@ragoona.com"
msg["Subject"] = "cf verify"
msg.set_content("hi")
msg.add_alternative('<a href="https://dash.cloudflare.com/verify-email?token=ABCdef_123-xyz">verify</a>', subtype="html")

s = smtplib.SMTP("127.0.0.1", 25, timeout=10)
s.send_message(msg)
s.quit()
EOF

  python3 - <<'EOF'
import sqlite3
conn = sqlite3.connect("/opt/farm/worker_farm.db", timeout=10)
cur = conn.cursor()
cur.execute("select id,email,link,status,created_at from verification_links order by id desc limit 1")
row = cur.fetchone()
print(row)
conn.close()
EOF
}

main() {
  need_root
  install_deps
  install_maddy
  ensure_user
  ensure_farm_user
  write_parser_and_db
  write_configs
  start_services
  if [[ "${1:-}" == "--test" ]]; then
    do_test
  fi
}

main "$@"

