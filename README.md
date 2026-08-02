# nothix

A third-party customer panel for [Datalix](https://datalix.eu) with a
Nothing inspired look. One Go binary, zero dependencies, talks straight to the
official [Datalix API](https://apidoc.datalix.de/).

> [!NOTE]
> A small project I built for fun, so **use at your own risk**. It does aim to be
> secure by default, see [security](docs/security.md).
>
> On the internet, put it behind nginx with SSL only, see [deploying](docs/deploying.md).
>
> Vibecoded under human supervision by **Opus & Claude Fable 5** running ultracode (ultra steroids).

> **Not affiliated with Datalix.**

![stack](https://img.shields.io/badge/go-stdlib_only-black)
![deps](https://img.shields.io/badge/dependencies-0-black)
![license](https://img.shields.io/badge/license-MIT-black)

## What it does

Manages **KVM servers**: power and rescue mode, reinstall, live graphs, traffic and
DDoS logs, IPs and rDNS, backups, scheduled tasks, ISOs, per-service SSH keys,
addons, upgrades, renewal and auto-renew, and ordering new ones. Plus the account
side: invoices, orders, transactions, credit, tickets you can actually answer,
access manager, email log and settings.

Every other product type (gameservers, webspace, Nextcloud, object storage,
colocation, IP subnets) is listed but opens in the official panel, and says so
before it takes you there.

## Quick start

```bash
go build -o nothix ./src
./nothix                          # http://127.0.0.1:8480
```

No Go toolchain:

```bash
docker compose up -d              # ghcr.io/lovinoes/nothix
```

Either way, log in with a Datalix API key (official panel → Other → API key).

## Docs

- [deploying.md](docs/deploying.md), Docker, nginx and TLS
- [security.md](docs/security.md), what the panel does with your API key
- [development.md](docs/development.md), layout, tests and the demo server

## Credits
- [Datalix GmbH](https://datalix.eu/) - https://datalix.eu/
- [NOTHING](https://nothing.tech) Tech. All Rights Reserved.
- [xeji01/nothingfont](https://github.com/xeji01/nothingfont) - https://github.com/xeji01/nothingfont
- [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) - https://github.com/DietrichGebert/ponytail
