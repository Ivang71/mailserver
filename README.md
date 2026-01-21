# ragoona mail inbound + api

## What runs

- **SMTP inbound**: `maddy` listens on `:25` and accepts any `*@ragoona.com`.
- **Parser**: mail is processed and extracted into the database (no mailbox/IMAP).
- **DB**: SQLite at `/opt/farm/worker_farm.db` (table `verification_links`).
- **API**: available at `https://api.ragoona.com`.

## Consumer overview (mail + api)

### What you do
1. Send/trigger an email to any address at `@ragoona.com`.
2. Poll the API for unread items.
3. Pick the item you want, use its `link`, then delete it via `/read`.

### API base
- Public: `https://api.ragoona.com`

### Endpoints
- `GET /unread`
  - Returns `[]` if none
  - Returns `[{"id":<int>,"email":"<addr@ragoona.com>","link":"<url>","created_at":"<ts>"}, ...]`
- `POST /read`
  - Body: `{"id":<int>}`
  - `200` → `{"deleted":true}`
  - `404` → `{"deleted":false}`

### Mail behavior
- Any recipient at `@ragoona.com` is accepted.
- Emails containing a Cloudflare verification URL appear via `GET /unread`.
- Cloudflare might get flaky, retry with short backoff.

## Install / reproduce on a new machine

### 1) Mail server + parser + API

```bash
sudo ./setup_inbound_mail.sh --test
```

### 2) Expose the API via Cloudflare Tunnel (no 80/443 needed)

This creates:
- a tunnel
- a DNS CNAME for `api.ragoona.com`
- a `cloudflared-api.service` systemd unit

```bash
export CF_API_TOKEN="(your token)"
sudo ./setup_cloudflare_tunnel_mail_api.sh
```

The tunnel runs using a tunnel **run token** stored in `/etc/cloudflared/api.token` (not your API token).
If your network blocks QUIC/UDP, the systemd unit forces HTTP/2 over TCP.

