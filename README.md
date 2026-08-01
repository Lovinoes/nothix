# panel
vibecoded 3rd-party dashboard for datalix 

![stack](https://img.shields.io/badge/go-stdlib_only-black) 

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
