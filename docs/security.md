# Security model

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

## Hosting this for other people

Don't, unless you understand what you are asking of them. The panel calls the
Datalix API on the user's behalf, so the server has to hold their key, and whoever
runs the server can read it: one log line, a debugger, a core dump, or a modified
binary. That is not a bug in nothix, it is what a server-side proxy is. Anyone
logging into your instance is handing you an unscoped credential that can reinstall
their servers, delete their backups and order products in their name.

Users cannot reach each other's keys through the app itself: the session id is 256
bits from `crypto/rand`, the key never reaches the browser, and the response cache
is partitioned per token. The weak points for a shared instance are elsewhere:

- Login is rate-limited per `r.RemoteAddr`, which behind nginx is the proxy. One
  shared budget of 5 attempts per 5 minutes for everybody, so one user fat-fingering
  their key locks out the rest, and it never bites a single attacker. A multi-user
  instance would have to key the limiter on `X-Forwarded-For`, trusted only from its
  own proxy.
- The limiter map is flushed wholesale above 10000 entries, so anyone who can reach
  the login page can reset it for everyone.
- Sessions are memory-only, so a restart or a container redeploy signs everyone out.

The `allow` / `deny` block in [deploying.md](deploying.md) is the intended
deployment: one operator, one key, nobody else on the port.

## What still needs the official panel

No third-party panel can mint an official datalix.de session, so the noVNC console,
email-log message contents and non-KVM services hand over to datalix.eu, each saying
so before it opens. Live graphs poll REST once a minute because the streaming
websocket only accepts official sessions.
