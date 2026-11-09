# Contributing to go-mms-trace

Thank you for your interest in contributing. Read [`AGENTS.md`](AGENTS.md) first: it lists the settled decisions and the hard rules.

## Development Setup

### Prerequisites

- Go 1.26+ (see [go.mod](go.mod)); CI and releases build with the current stable Go
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/) v2 and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the checks
- No privileges and no real captures: the tests record go-mms associations on 127.0.0.1 and build their captures ([TESTING.md](TESTING.md))

### Build & Test

```sh
make check     # format, mod check, lint, vet, vulnerability scan, race tests, coverage gates, cross-builds, docsync
make build     # ./bin/mmstracectl
make fuzz      # every fuzz target for FUZZ_TIME (default 30s)
make golden    # regenerate testdata/*.pcap and the CLI's golden outputs
```

Run `make` (or `make help`) for the full list of targets.

### The CLI module

`cmd/mmstracectl` is a nested module. During development its `go.mod` has `replace github.com/otfabric/go-mms-trace => ../..`; at release that line is replaced by a version pin of the library (as `cmd/mbtracectl` pins go-modbus-trace), so a release of the CLI builds on a released library. `make mod-check` checks the library's `go.mod` only.

## Rules

- **Offline only.** The library never captures live, never opens a socket and never reads the wall clock for anything it outputs. `depguard` and `forbidigo` enforce it for non-test code.
- **Pure Go**, `CGO_ENABLED=0`, on every target in the Makefile's `TARGETS`.
- **Bounded buffers**: every buffer of the pipeline has a cap and a counter ([ARCHITECTURE.md](ARCHITECTURE.md) section 2).
- **Hostile input:** readers and decoders never panic and never allocate beyond their limits; a new parser comes with a fuzz target.
- **No customer captures** in the repository, ever.
- **Docs in the same change:** if a document is wrong, fix it in the same pull request.

## Pull Requests

- Branch from `main`, targeting `main`.
- `make check` passes locally.
- Add an entry to [`RELEASE.md`](RELEASE.md) for anything a user notices.
