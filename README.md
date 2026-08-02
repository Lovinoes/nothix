# nothix

A third-party customer panel for [Datalix](https://datalix.eu) with a
Nothing-OS-inspired look. One Go binary, zero dependencies, talks straight to the
official [Datalix API](https://apidoc.datalix.de/).

> [!NOTE]
> A small project I built for fun, so **use at your own risk**. That said, it aims to
> be secure by default: your API key never leaves the server's memory, every POST is
> CSRF- and origin-checked, and the page makes no external requests at all. If you
> put it on the internet, run it behind nginx with SSL only. See
> [Deploying it](#deploying-it).
>
> Vibecoded under human supervision by **Opus & Claude Fable 5** running ultracode (ultra steroids).

> **Not affiliated with Datalix.**

![stack](https://img.shields.io/badge/go-stdlib_only-black)
![deps](https://img.shields.io/badge/dependencies-0-black)
![license](https://img.shields.io/badge/license-MIT-black)

## What it does

Nothix manages **KVM servers**. Every other product type (gameservers, webspace,
Nextcloud, object storage, colocation, IP subnets) is still listed, but opens in the
official panel, and clicking one says so before it takes you there.

**KVM server management**
- Power (start / restart / shutdown / stop / force stop), rescue mode, reinstall,
  password reset, rename
- Live CPU / memory / network graphs, traffic history and traffic notifications
- IPs: rDNS for v4 and v6 (set or reset to default), per-IP DDoS protection mode,
  notes, mail-port unlock
- Backups: create, restore, rename, lock/unlock, delete, cancel a planned one
- Scheduled tasks with per-task "email on finish / on failure" toggles
- DDoS log with search and pagination, plus attack notifications
- ISO: standard images and custom ISO download / mount, TPM and UEFI toggles,
  uplink limit
- Per-service SSH keys, addons (order and delete), package upgrades
- Renewal, auto-renew via credit or PayPal / credit card, noVNC (via the official panel)
- Order new KVM servers directly in the panel

**Account & accounting**
- Dashboard with credit, support PIN, activity feed and all your services
- Invoices (view/download the PDF), orders, transactions, purchase by invoice
- Top up credit with every payment method, donation links, affiliate links
- Tickets: list, create, read the thread and answer, all in the panel
- Access manager, email log, support info
- Settings: 2FA, invoice data, SSH keys, notification webhooks, active sessions

**Little things**
- Sensitive values (support PIN, access code, session IPs, invoice data, webhook
  URLs) are blurred until you hover. Click the PIN or access code to copy it
- Destructive actions ask first
- Works with password managers (no root-zoom trickery breaking their overlays)

## Quick start

```bash
go build -o nothix .
./nothix                          # http://127.0.0.1:8480
```

Log in with a Datalix API key (official panel → Other → API key). The user ID is
auto-detected; paste it manually only if detection fails.

Want to click around without an account? There is a demo server backed by a mock
API that includes one of every product type:

```bash
go test -run TestDemoServer -timeout 0 -demo
```

It listens on `http://127.0.0.1:8481`. Log in with the key `testkey_abcdef123456`.

## Deploying it

Nothix speaks plain HTTP and binds to localhost. **Do not expose that port
directly.** Put nginx in front, terminate TLS there, and serve HTTPS only.

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name panel.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name panel.example.com;

    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;
    ssl_protocols       TLSv1.3;
    ssl_ecdh_curve      X25519MLKEM768:X25519;   # post-quantum, classical fallback
    ssl_session_cache   shared:TLS:10m;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    server_tokens        off;
    client_max_body_size 1m;      # the panel caps its own bodies at 64 KB

    # single user? uncomment and put your own addresses here
    # allow 203.0.113.7;
    # allow 2001:db8:1234:5678::/64;
    # deny  all;

    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;   # required, see below

    # Timeouts
    proxy_connect_timeout 5s;
    proxy_send_timeout    60s;
    proxy_read_timeout    60s;
    # Buffering
    proxy_buffer_size 8k;
    proxy_buffers     16 4k;

    location / {
        proxy_pass http://127.0.0.1:8480;
    }

    location /static/ {           # assets only, never the HTML
        gzip       on;
        gzip_types text/css application/javascript font/ttf font/otf;
        proxy_pass http://127.0.0.1:8480;
    }
}

server {                          # stray hostnames and direct-IP hits
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
    return 444;
}
```

Why it looks like that:

- `X-Forwarded-Proto` is not optional. It is how the panel knows to mark its
  session cookie `Secure`. Without it, that cookie can go out over plain HTTP.
- TLS 1.3 only, with `X25519MLKEM768` first so the key exchange is post-quantum
  where the client supports it and falls back to plain X25519 where it does not.
  That group name needs nginx built against OpenSSL 3.5 or newer, so check
  `nginx -V` first. On anything older nginx refuses to start, and the line
  becomes `ssl_ecdh_curve X25519:prime256v1;`.
- gzip is scoped to `/static/` on purpose. Compressing the HTML would put a CSRF
  token and reflected search terms in the same compressed response, which is the
  setup BREACH needs. The assets are where the win is anyway: the bundled fonts
  are plain `ttf` and `otf` and shrink by roughly half.
- No `expires` anywhere, because the panel already sends its own `Cache-Control`
  (fonts for a day, CSS and JS revalidating). Overriding that from nginx would
  serve stale UI after a rebuild.
- HSTS is the only header added. The panel already sends its own CSP,
  `X-Frame-Options`, `Referrer-Policy`, `X-Content-Type-Options`,
  `Permissions-Policy` and `Cross-Origin-Opener-Policy`, and a second copy from
  nginx would duplicate or fight with those.
- The last block answers anything aimed at another hostname or the bare IP with
  no TLS handshake and no response, so the panel is reachable only under its own
  name.

Leave `PANEL_ADDR` on loopback so only nginx can reach the panel:

| Env | Default | |
|-----|---------|-|
| `PANEL_ADDR` | `127.0.0.1:8480` | listen address |

Anyone who reaches the panel can use whatever API key is logged in, so keep the
`allow` / `deny` block above, or put HTTP basic auth in front, unless it is only
ever you on a trusted network.

## Security model

- Your API key lives **only in the panel's server memory**, tied to a random
  session cookie. It is never sent to the browser, never written to disk, and is
  dropped on logout or after 12 h of inactivity (sliding).
- Session cookies are `HttpOnly` and `SameSite=Strict`, plus `Secure` whenever the
  request arrives over HTTPS.
- Every POST carries a per-session CSRF token compared in constant time, and the
  `Origin` header is checked on top of that.
- Request bodies are capped at 64 KB. Login is rate-limited to 5 attempts per
  5 minutes per client address, though behind a reverse proxy the panel only ever
  sees the proxy, so that budget ends up shared by everyone reaching it.
- Strict CSP: no external scripts, styles, images, fonts or connections.
  Everything is embedded in the binary. The panel itself talks to exactly one
  host, the Datalix API.
- The binary executes nothing and writes no files.

Input from the browser is validated before it reaches the API, and output goes
through Go's contextual auto-escaping templates.

## What still needs the official panel

A third-party panel cannot mint an official datalix.de session, so a few things
hand over (each says so before it opens datalix.eu):

- the noVNC console
- reading email-log message contents
- managing non-KVM services

Live graphs poll the REST API once a minute instead of streaming: the official
websocket only accepts official sessions, and the REST endpoint is rate-limited.

## Development

```bash
go test ./...          # one end-to-end smoke test against a mocked API
go vet ./...
```

Four files: `main.go` (routing, sessions, templates), `handlers.go` (pages and
actions), `datalix.go` (API client and response types), `main_test.go` (smoke test
plus the demo server's mock API). Templates and static assets are embedded with
`go:embed`, so rebuild after editing them.

## Fonts

Nothing (Ndot57 / NType82) typefaces bundled from
[xeji01/nothingfont](https://github.com/xeji01/nothingfont) via
[ndot-logo-generator](https://github.com/Lovinoes/ndot-logo-generator).

## License

MIT, see [LICENSE](LICENSE). © 2026 Lovinoes.
