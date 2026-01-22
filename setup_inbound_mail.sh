#!/usr/bin/env bash
set -euo pipefail

MADDY_VERSION="${MADDY_VERSION:-0.7.1}"
PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-ragoona.com}"
MX_HOSTNAME="${MX_HOSTNAME:-$PRIMARY_DOMAIN}"
FARM_DIR="${FARM_DIR:-/opt/farm}"
API_PORT="${API_PORT:-8091}"

MADDY_BIN="/usr/local/bin/maddy"
MADDY_CONF_DIR="/etc/maddy"
MADDY_CONF="${MADDY_CONF_DIR}/maddy.conf"

PARSER="${FARM_DIR}/parse_email.py"
SINK="${FARM_DIR}/smtp_sink.py"
API="${FARM_DIR}/mail_api.py"
DB="${FARM_DIR}/worker_farm.db"
PY_VENV_DIR="${PY_VENV_DIR:-${FARM_DIR}/venv}"

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

need_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemd required (systemctl not found)"
}

fetch_url() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return 0
  fi
  die "need curl or wget"
}

pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo apt; return 0; fi
  if command -v dnf >/dev/null 2>&1; then echo dnf; return 0; fi
  if command -v yum >/dev/null 2>&1; then echo yum; return 0; fi
  if command -v pacman >/dev/null 2>&1; then echo pacman; return 0; fi
  echo ""
}

pkg_install() {
  local mgr
  mgr="$(pkg_mgr)"
  [[ -n "$mgr" ]] || die "no supported package manager found (apt/dnf/yum/pacman)"
  case "$mgr" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    pacman) pacman -Sy --noconfirm --needed "$@" ;;
  esac
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
  command -v tar >/dev/null 2>&1 || pkg_install tar
  command -v zstd >/dev/null 2>&1 || pkg_install zstd

  local arch
  arch="$(uname -m)"
  local rel_arch
  case "$arch" in
    x86_64|amd64) rel_arch="x86_64" ;;
    aarch64|arm64) rel_arch="arm64" ;;
    *) rel_arch="" ;;
  esac

  if [[ -z "$rel_arch" ]]; then
    die "unsupported arch for release install: ${arch} (set MADDY_BIN to an existing maddy or install manually)"
  fi
  local tarzst="/tmp/maddy-${MADDY_VERSION}.tar.zst"
  fetch_url "$(
    printf '%s' "https://github.com/foxcpp/maddy/releases/download/v${MADDY_VERSION}/maddy-${MADDY_VERSION}-${rel_arch}-linux-musl.tar.zst"
  )" "$tarzst"
  rm -rf "/tmp/maddy-${MADDY_VERSION}-${rel_arch}-linux-musl"
  tar --zstd -xf "$tarzst" -C /tmp
  install -m 0755 "/tmp/maddy-${MADDY_VERSION}-${rel_arch}-linux-musl/maddy" "$MADDY_BIN"
}

install_deps() {
  command -v python3 >/dev/null 2>&1 || die "python3 required"
  if [[ ! -x "${PY_VENV_DIR}/bin/python" ]]; then
    case "$(pkg_mgr)" in
      apt) pkg_install python3-venv python3-pip ;;
      dnf|yum) pkg_install python3-pip ;;
      pacman) pkg_install python-pip ;;
      *) die "cannot prepare python venv (no pkg manager)" ;;
    esac
    python3 -m venv "$PY_VENV_DIR"
  fi

  "${PY_VENV_DIR}/bin/pip" install --no-input --disable-pip-version-check --no-cache-dir aiosmtpd >/dev/null || true
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

  command -v openssl >/dev/null 2>&1 || pkg_install openssl
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

if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -qE '^Status:\s+active'; then
    ufw allow 25/tcp >/dev/null 2>&1 || true
  fi
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  if firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=smtp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
fi

if command -v nft >/dev/null 2>&1; then
  if nft list chain inet eus_firewall input >/dev/null 2>&1; then
    if ! nft list chain inet eus_firewall input 2>/dev/null | grep -qE 'tcp dport 25 accept'; then
      nft add rule inet eus_firewall input tcp dport 25 accept >/dev/null 2>&1 || true
    fi
  fi
fi
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
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=${PY_VENV_DIR}/bin/python ${SINK}
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
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
User=farmapi
Group=farm
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStartPre=${PY_VENV_DIR}/bin/python -B -m py_compile ${API}
ExecStart=${PY_VENV_DIR}/bin/python ${API} --bind 127.0.0.1 --port ${API_PORT}
Restart=always
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
import sqlite3
import sys
from email import message_from_bytes
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

raw = sys.stdin.buffer.read()
msg = message_from_bytes(raw)

mail_from = (msg.get("from") or "").strip()
rcpt_to = (msg.get("to") or "").strip()
subject = (msg.get("subject") or "").strip()

to_hdr = msg.get_all("to", [])
addr = getaddresses(to_hdr)
recipient = addr[0][1] if addr else ""


class HrefParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for k, v in attrs:
            if k.lower() == "href" and v:
                self.hrefs.append(v)


def decode(part):
    payload = part.get_payload(decode=True) or b""
    cs = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(cs, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def iter_text_parts(m):
    if m.is_multipart():
        for p in m.walk():
            ct = p.get_content_type()
            if ct in ("text/plain", "text/html"):
                yield ct, decode(p)
        return
    ct = m.get_content_type()
    if ct in ("text/plain", "text/html"):
        yield ct, decode(m)


def extract_urls(parts):
    urls = set()
    for ct, text in parts:
        if not text:
            continue
        if ct == "text/html":
            p = HrefParser()
            p.feed(text)
            for u in p.hrefs:
                urls.add(u)
        for u in text.replace("\r", " ").replace("\n", " ").split():
            if u.startswith("http://") or u.startswith("https://"):
                urls.add(u.strip(" \t\r\n\"'<>(),.;"))
    return urls


def is_verify(u):
    if "verif" not in u.lower():
        return False
    p = urlparse(u)
    if p.netloc.lower() != "dash.cloudflare.com":
        return False
    token = (parse_qs(p.query).get("token") or [""])[0]
    return bool(token)


conn = sqlite3.connect("/opt/farm/worker_farm.db", timeout=10)
cur = conn.cursor()
cur.execute(
    "CREATE TABLE IF NOT EXISTS raw_emails (id INTEGER PRIMARY KEY AUTOINCREMENT, mail_from TEXT, rcpt_to TEXT, subject TEXT, raw BLOB, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
)
cur.execute("delete from raw_emails where created_at < datetime('now','-1 hour')")
cur.execute(
    "INSERT INTO raw_emails (mail_from, rcpt_to, subject, raw) VALUES (?, ?, ?, ?)",
    (mail_from, rcpt_to, subject, sqlite3.Binary(raw)),
)

parts = list(iter_text_parts(msg))
urls = [u for u in extract_urls(parts) if is_verify(u)]
if not urls:
    conn.commit()
    conn.close()
    sys.exit(0)
link = sorted(urls)[0]

cur.execute(
    "CREATE TABLE IF NOT EXISTS verification_links (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, link TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
)
cur.execute("delete from verification_links where status='pending' and created_at < datetime('now','-1 hour')")
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
TTL_SECONDS = 3600


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj=None):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if obj is not None:
                self.wfile.write(json.dumps(obj, separators=(",", ":")).encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError):
            return

    def _cleanup(self, cur):
        cur.execute(
            "delete from verification_links where status='pending' and created_at < datetime('now','-1 hour')"
        )

    def do_GET(self):
        try:
            if self.path != "/unread":
                self._json(404, {"error": "not_found"})
                return

            conn = sqlite3.connect(DB_PATH, timeout=10)
            try:
                cur = conn.cursor()
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS verification_links (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, link TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
                )
                self._cleanup(cur)
                cur.execute(
                    "select id,email,link,created_at from verification_links where status='pending' order by id asc"
                )
                rows = cur.fetchall()
                conn.commit()
            finally:
                conn.close()

            self._json(
                200,
                [{"id": r[0], "email": r[1], "link": r[2], "created_at": r[3]} for r in rows],
            )
        except sqlite3.OperationalError:
            self._json(500, {"error": "db_error"})
        except Exception:
            self._json(500, {"error": "internal_error"})

    def do_POST(self):
        try:
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

            conn = sqlite3.connect(DB_PATH, timeout=10)
            try:
                cur = conn.cursor()
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS verification_links (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, link TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
                )
                self._cleanup(cur)
                cur.execute("delete from verification_links where id=? and status='pending'", (rid,))
                deleted = cur.rowcount
                conn.commit()
            finally:
                conn.close()

            if deleted:
                self._json(200, {"deleted": True})
            else:
                self._json(404, {"deleted": False})
        except sqlite3.OperationalError:
            self._json(500, {"error": "db_error"})
        except Exception:
            self._json(500, {"error": "internal_error"})

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

  "${PY_VENV_DIR}/bin/python" - <<EOF
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
  systemctl restart farm-smtp-sink.service
  systemctl enable --now farm-mail-api.service
  systemctl restart farm-mail-api.service
  systemctl reset-failed maddy.service 2>/dev/null || true
  systemctl enable --now maddy.service
  systemctl restart maddy.service
}

do_test() {
  "${PY_VENV_DIR}/bin/python" - <<'EOF'
import smtplib
import time
from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "tester@ragoona.com"
msg["To"] = "user999@ragoona.com"
msg["Subject"] = "cf verify"
msg.set_content("hi")
msg.add_alternative('<a href="https://dash.cloudflare.com/verify-email?token=ABCdef_123-xyz">verify</a>', subtype="html")

last = None
for _ in range(60):
    try:
        s = smtplib.SMTP("127.0.0.1", 25, timeout=10)
        break
    except OSError as e:
        last = e
        time.sleep(0.2)
else:
    raise SystemExit(str(last))
s.send_message(msg)
s.quit()
EOF

  "${PY_VENV_DIR}/bin/python" - <<'EOF'
import sqlite3
conn = sqlite3.connect("/opt/farm/worker_farm.db", timeout=10)
cur = conn.cursor()
cur.execute("select id,email,link,status,created_at from verification_links order by id desc limit 1")
row = cur.fetchone()
print(row)
conn.close()
EOF

  "${PY_VENV_DIR}/bin/python" - <<'EOF'
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8091/unread", timeout=5) as r:
  body = r.read().decode("utf-8")
obj = json.loads(body)
print(len(obj))
EOF
}

main() {
  need_root
  need_systemd
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

