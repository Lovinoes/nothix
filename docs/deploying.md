# Deploying

Nothix speaks plain HTTP and binds to localhost. **Do not expose that port
directly.** Put nginx in front, terminate TLS there, and serve HTTPS only.

`PANEL_ADDR` sets the listen address and defaults to `127.0.0.1:8480`. Leave it on
loopback so only nginx can reach the panel.

## Docker

Images are published to GHCR for `linux/amd64` and `linux/arm64` on every push to
`main`. Tags are `latest`, `sha-<commit>` for pinning, and `1.2.3` plus `1.2` for
`v*` git tags.

```bash
docker compose up -d                          # see compose.yaml
docker pull ghcr.io/lovinoes/nothix:latest    # or just the image
docker build -t nothix .                      # or from a checkout
```

The image is `FROM scratch`: a static binary, a CA bundle so it can reach the
Datalix API, and nothing else. No shell, no package manager, uid 65534, read-only
root filesystem, which costs nothing since the panel writes no files anyway.

`PANEL_ADDR` is `0.0.0.0:8480` inside the container and the image already defaults
to that. Privacy comes from the port mapping instead: `127.0.0.1:8480:8480`
publishes to the host's loopback only, so nginx still terminates TLS in front of it.
Sessions live in memory, so restarting the container logs you out.

## nginx

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

Anyone who reaches the panel can use whatever API key is logged in, so keep the
`allow` / `deny` block unless it is only ever you on a trusted network.
