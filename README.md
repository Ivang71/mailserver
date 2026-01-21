# ragoona mail inbound + api

## What runs

- **SMTP inbound**: `maddy` listens on `:25` and accepts any `*@ragoona.com`.
- **Parser**: mail is forwarded to a local SMTP sink which feeds raw messages into `/opt/farm/parse_email.py`.
- **DB**: SQLite at `/opt/farm/worker_farm.db` (table `verification_links`).
- **API (localhost-only)**: `farm-mail-api` listens on `127.0.0.1:8091`.
  - `GET /unread` → returns the next pending row or `204` if none.
  - `POST /read` with JSON `{"id": <int>}` → deletes that row (only if `status='pending'`).

## Install / reproduce on a new machine

### 1) Mail server + parser + local API

```bash
sudo /root/mail/setup_inbound_mail.sh --test
```

### 2) Expose the API via Cloudflare Tunnel (no 80/443 needed)

This creates:
- a tunnel
- a DNS CNAME for `mailapi.ragoona.com`
- a `cloudflared-mailapi.service` systemd unit

```bash
export CF_API_TOKEN="(your token)"
sudo /root/mail/setup_cloudflare_tunnel_mail_api.sh
```

The tunnel runs using a tunnel **run token** stored in `/etc/cloudflared/mailapi.token` (not your API token).
If your network blocks QUIC/UDP, the systemd unit forces HTTP/2 over TCP.

