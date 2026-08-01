# nothix

A vibecoded third-party customer panel for [Datalix](https://datalix.eu) with a
Nothing-OS-inspired look. One Go binary, zero dependencies, talks straight to the
official [Datalix API](https://apidoc.datalix.de/).

> [!NOTE]
> work in progress
> 
> Vibecoded under human supervision by **Claude Fable 5** running ultracode (ultra steroids).

> **Not affiliated with Datalix. Use at your own risk.**

![stack](https://img.shields.io/badge/go-stdlib_only-black)
![deps](https://img.shields.io/badge/dependencies-0-black)
![license](https://img.shields.io/badge/license-MIT-black)

## Features

**KVM server management**
- Power (start / stop / shutdown / restart / rescue), reinstall, password reset
- Live CPU / memory / network graphs, traffic history charts and notifications
- IPs: rDNS (v4 + v6), per-IP DDoS protection mode, notes
- Backups (create / restore / rename / lock), scheduled tasks (cron), DDoS log
- ISO: standard images plus custom ISO download / mount, TPM & UEFI toggles, uplink
- Renewal, auto-renew via credit or PayPal / credit card, noVNC (via official panel)
- Order new KVM servers directly in the panel

**Account & accounting**
- Dashboard with credit, support PIN, activity feed and all services
- Invoices (view/download the PDF), orders, transactions, purchase by invoice
- Top up credit with all payment methods, donation links, affiliate links
- Tickets (view + create), support PIN, access manager, email log
- Settings: language, 2FA, invoice data, SSH keys, notification webhooks, sessions

**Little things**
- Sensitive values (support PIN, access code, session IPs, invoice data, webhook
  URLs) are blurred until hover — click the PIN or access code to copy it
- Works with password managers (no root zoom trickery breaking their overlays)

## Run

```bash
go build -o panel.exe .
./panel.exe                      # http://127.0.0.1:8480
```

Log in with a Datalix API key (official panel → Account → API key). The user ID
is auto-detected; paste it manually only if detection fails.

| Env | Default | |
|-----|---------|-|
| `PANEL_ADDR` | `127.0.0.1:8480` | listen address — put TLS in front if you expose it |

## Security model

- Your API key lives **only in the panel's server memory**, tied to a random
  session cookie. It is never sent to the browser, never written to disk, and
  dropped on logout or after 12 h of inactivity (sliding).
- Every POST is CSRF-protected and origin-checked.
- Strict CSP: no external scripts, styles, images or connections — everything
  (fonts, payment icons, chart code) is embedded in the binary.

## Limitations

A third-party panel can't mint an official datalix.de session, so a few things
hand over to the official panel: the noVNC console, reading email-log contents,
and answering ticket messages. Live graphs poll the REST API once a minute
(the endpoint is rate-limited; the official websocket only accepts official
sessions).

## Test

```bash
go test ./...
```

## Fonts

Nothing (Ndot57 / NType82) typefaces bundled from
[xeji01/nothingfont](https://github.com/xeji01/nothingfont) via
[ndot-logo-generator](https://github.com/Lovinoes/ndot-logo-generator).

## License

MIT — see [LICENSE](LICENSE). © Nothix maintainers and contributors.
