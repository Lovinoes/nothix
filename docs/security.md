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

## What still needs the official panel

No third-party panel can mint an official datalix.de session, so the noVNC console,
email-log message contents and non-KVM services hand over to datalix.eu, each saying
so before it opens. Live graphs poll REST once a minute because the streaming
websocket only accepts official sessions.
