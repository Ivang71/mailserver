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
3. Pick the item you want, use its `link` (URL or code), then delete it via `/read`.

### API base
- Public: `https://api.ragoona.com`

### Endpoints
- `GET /unread`
  - Returns `[]` if none
  - Returns `[{"id":<int>,"email":"<addr@ragoona.com>","link":"<url>","code":"<numeric_code>","created_at":"<ts>"}, ...]`
  - `link` will be a URL string (or empty string/null if only code found)
  - `code` will be a numeric string (or empty string/null if only link found)
- `GET /email?id=<int>`
  - Returns the full raw RFC822 email content (headers + body)
  - Useful for debugging if extraction fails
- `POST /read`
  - Body: `{"id":<int>}`
  - `200` → `{"deleted":true}`
  - `404` → `{"deleted":false}`

### Mail behavior
- Any recipient at `@ragoona.com` is accepted.
- Emails are parsed immediately for Cloudflare verification links or codes.
- Full raw emails are stored for 1 hour in `raw_emails` (debug/fallback).
- Extracted links/codes are stored in `verification_links` (returned by `/unread`).
- Cloudflare might get flaky, retry with short backoff.

## Install / reproduce on a new machine

### 0) Server DNS (resolver)

`setup_inbound_mail.sh` now pins a static resolver config at `/etc/resolv.conf.static` and symlinks `/etc/resolv.conf` to it, so DNS keeps working even if `systemd-resolved` dies.

Override via:

```bash
export UPSTREAM_DNS="1.1.1.1 1.0.0.1 8.8.8.8"
```

### 1) Mail server + parser + API

```bash
sudo ./setup_inbound_mail.sh --test
```

### 2) Cloudflare DNS for inbound mail (MX + A)

This creates/updates:
- `A ${MX_HOSTNAME} -> (this server public IP)` (unproxied)
- `MX ${DOMAIN} -> ${MX_HOSTNAME}` (priority 10 by default)

```bash
export CF_API_TOKEN="(your token)"
sudo ./setup_cloudflare_dns_inbound_mail.sh
```

### 3) Expose the API via Cloudflare Tunnel (no 80/443 needed)

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

