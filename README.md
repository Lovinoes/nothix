# nothix
vibecoded 3rd-party dashboard for datalix — not affiliated with Datalix. Use at your own risk.

![stack](https://img.shields.io/badge/go-stdlib_only-black) ![license](https://img.shields.io/badge/license-MIT-black)

## Run

```
go build -o panel.exe .
./panel.exe                      # http://127.0.0.1:8480
```

Log in with a Datalix API key (official panel → Account → API). The user ID is
auto-detected; paste it manually only if detection fails.

## Test

```
go test ./...
```

## Fonts

Nothing (Ndot57 / NType82) typefaces bundled from
[xeji01/nothingfont](https://github.com/xeji01/nothingfont) via
[ndot-logo-generator](https://github.com/Lovinoes/ndot-logo-generator).

## License

MIT — see [LICENSE](LICENSE). © Nothix maintainers and contributors.
