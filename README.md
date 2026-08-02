# nothix

A third-party customer panel for [Datalix](https://datalix.eu) with a
Nothing-OS-inspired look. One Go binary, zero dependencies, talks straight to the
official [Datalix API](https://apidoc.datalix.de/).

> [!NOTE]
> A small project I built for fun, so **use at your own risk**. It does aim to be
> secure by default: your API key never leaves the server's memory, every POST is
> CSRF- and origin-checked, and the page makes no external requests at all. On the
> internet, put it behind nginx with SSL only, see [Deploying it](#deploying-it).
>
> Vibecoded under human supervision by **Opus & Claude Fable 5** running ultracode (ultra steroids).

> **Not affiliated with Datalix.**

![stack](https://img.shields.io/badge/go-stdlib_only-black)
![deps](https://img.shields.io/badge/dependencies-0-black)
![license](https://img.shields.io/badge/license-MIT-black)

## What it does

Manages **KVM servers**: power and rescue mode, reinstall, live CPU / memory /
network graphs, traffic and DDoS logs with notifications, IPs (rDNS for v4 and v6,
per-IP DDoS mode, mail-port unlock), backups, scheduled tasks, ISOs with TPM and
UEFI toggles, SSH keys, addons, upgrades, renewal and auto-renew, and ordering new
ones.

Plus the whole account side: dashboard, invoices, orders, transactions, credit
top-up, donation and affiliate links, tickets you can actually answer, access
manager, email log, and settings (2FA, invoice data, SSH keys, webhooks, sessions).

Every other product type (gameservers, webspace, Nextcloud, object storage,
colocation, IP subnets) is listed but opens in the official panel, and says so
before it takes you there.

Sensitive values are blurred until you hover, and destructive actions ask first.

## Quick start

```bash
go build -o nothix ./src
./nothix                          # http://127.0.0.1:8480
```

Log in with a Datalix API key (official panel → Other → API key). No Go toolchain?
`docker compose up -d`, see [Docker](#docker).

A demo server backed by a mock API needs no account at all:

```bash
go test -C src -run TestDemoServer -timeout 0 -demo
```

That one listens on `http://127.0.0.1:8481`, key `testkey_abcdef123456`.

## Docker

Published to GHCR for `linux/amd64` and `linux/arm64` on every push to `main`. Tags
are `latest`, `sha-<commit>` for pinning, and `1.2.3` plus `1.2` for `v*` git tags.

```bash
docker compose up -d                          # see compose.yaml
docker pull ghcr.io/lovinoes/nothix:latest    # or just the image
```

The image is `FROM scratch`: a static binary, a CA bundle so it can reach the
Datalix API, and nothing else. No shell, no package manager, uid 65534, read-only
root filesystem, which costs nothing since the panel writes no files anyway.

`PANEL_ADDR` is `0.0.0.0:8480` inside the container and the image already defaults
to that. Privacy comes from the port mapping instead: `127.0.0.1:8480:8480`
publishes to the host's loopback only, so nginx still terminates TLS in front of it.
Sessions live in memory, so restarting the container logs you out. To build from a
checkout, `docker build -t nothix .`.

## Deploying it

Nothix speaks plain HTTP and binds to localhost. **Do not expose that port
directly.** Put nginx in front, terminate TLS there, and serve HTTPS only.

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name nothix.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name nothix.example.com;

    ssl_certificate     /etc/letsencrypt/live/nothix.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nothix.example.com/privkey.pem;
    ssl_protocols       TLSv1.3;
    ssl_ecdh_curve      X25519MLKEM768:X25519;   # post-quantum, classical fallback
    ssl_session_cache   shared:TLS:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
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
```

Why it looks like that:

- `X-Forwarded-Proto` is not optional. It is how the panel knows to mark its
  session cookie `Secure`.
- TLS 1.3 only, `X25519MLKEM768` first so the key exchange is post-quantum where
  the client supports it, X25519 where it does not. That group needs nginx built
  against OpenSSL 3.5 or newer, so check `nginx -V`. On older builds it refuses to
  start and the line becomes `ssl_ecdh_curve X25519:prime256v1;`.
- gzip is scoped to `/static/`. Compressing the HTML would put a CSRF token and
  reflected search terms in one compressed response, which is the setup BREACH
  needs, and the bundled `ttf` and `otf` fonts are where the win is anyway.
- No `expires` and no other added headers: the panel already sends its own
  `Cache-Control`, CSP, `X-Frame-Options`, `Referrer-Policy` and the rest. HSTS is
  the single addition.
- The last block answers stray hostnames and bare-IP hits with no TLS handshake and
  no response at all.

`PANEL_ADDR` defaults to `127.0.0.1:8480`, so leave it on loopback and only nginx
can reach the panel. Anyone who does reach it can use whatever API key is logged in,
so keep the `allow` / `deny` block unless it is only ever you on a trusted network.

## Security model

- The API key lives **only in the panel's server memory**, tied to a random session
  cookie. Never sent to the browser, never written to disk, dropped on logout or
  after 12 h of inactivity (sliding).
- Session cookies are `HttpOnly` and `SameSite=Strict`, plus `Secure` whenever the
  request arrives over HTTPS.
- Every POST carries a per-session CSRF token compared in constant time, and the
  `Origin` header is checked on top of that.
- Bodies are capped at 64 KB. Login allows 5 attempts per 5 minutes per client
  address, though behind a reverse proxy the panel only ever sees the proxy, so that
  budget ends up shared by everyone reaching it.
- Strict CSP with everything embedded in the binary and exactly one outbound host.
  The binary executes nothing and writes no files. Input is validated before it
  reaches the API, output goes through Go's contextual auto-escaping templates.

## What still needs the official panel

No third-party panel can mint an official datalix.de session, so the noVNC console,
email-log message contents and non-KVM services hand over to datalix.eu, each saying
so before it opens. Live graphs poll REST once a minute because the streaming
websocket only accepts official sessions.

## Development

```bash
go test ./...          # one end-to-end smoke test against a mocked API
go vet ./...
```

All of it is in [src/](src): `main.go` (routing, sessions, templates),
`handlers.go` (pages and actions), `datalix.go` (API client and response types),
`main_test.go` (smoke test plus the demo server's mock API). `templates/` and
`static/` sit beside them and are embedded with `go:embed`, so rebuild after
editing those.

## Credits
- [Datalix](https://datalix.eu/) - https://datalix.eu/
- [NOTHING](https://nothing.tech) Tech. All Rights Reserved.
- [xeji01/nothingfont](https://github.com/xeji01/nothingfont) - https://github.com/xeji01/nothingfont

