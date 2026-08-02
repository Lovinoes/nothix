# Development

```bash
go build -o nothix ./src
go test ./...          # one end-to-end smoke test against a mocked API
go vet ./...
```

All of it is in [../src](../src): `main.go` (routing, sessions, templates),
`handlers.go` (pages and actions), `datalix.go` (API client and response types),
`main_test.go` (smoke test plus the demo server's mock API). `templates/` and
`static/` sit beside them and are embedded with `go:embed`, so rebuild after
editing those. The repo root holds `go.mod`, the container files and the docs.

## Demo server

A mock API with one of every product type, no account needed:

```bash
go test -C src -run TestDemoServer -timeout 0 -demo
```

It listens on `http://127.0.0.1:8481`, key `testkey_abcdef123456`.
