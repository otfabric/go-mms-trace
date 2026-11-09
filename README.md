# go-mms-trace

[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-mms-trace.svg)](https://pkg.go.dev/github.com/otfabric/go-mms-trace)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Status](https://github.com/otfabric/go-mms-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-mms-trace/actions/workflows/ci.yml)
[![Code Coverage](https://codecov.io/gh/otfabric/go-mms-trace/graph/badge.svg)](https://codecov.io/gh/otfabric/go-mms-trace)
[![Latest Release](https://img.shields.io/github/v/release/otfabric/go-mms-trace?label=release)](https://github.com/otfabric/go-mms-trace/releases)

Read a packet capture (pcap or pcapng, plain or gzip) of IEC 61850 traffic and get what it holds:

- the **MMS associations** over ISO-on-TCP (RFC 1006: TPKT, COTP, session, presentation, ACSE, MMS), with how each was opened and closed, whether it was accepted and which authentication mechanism the AARQ named;
- their **confirmed services**, request and response paired by invoke ID, with a status (`ok`, `error`, `reject`, `unanswered`, `orphan`, `pending`) and the latency;
- the unconfirmed **InformationReports** (IEC 61850 reports);
- the **GOOSE** and **Sampled Values** streams on Ethernet, with their sequencing issues;
- counters of everything that could not be used.

MMS is decoded by [go-mms](https://github.com/otfabric/go-mms) (`mms.DecodeTSDU`), COTP by [go-cotp](https://github.com/otfabric/go-cotp), GOOSE and Sampled Values by [go-iec61850](https://github.com/otfabric/go-iec61850).

Offline only: the library never captures live and never sends anything. Pure Go, no cgo, no libpcap. What it cannot do is in [LIMITATIONS.md](LIMITATIONS.md).

## mmstracectl

### Install mmstracectl

```sh
curl -fsSL https://get.otfabric.io/mmstracectl | sh
```

```powershell
irm https://get.otfabric.io/mmstracectl.ps1 | iex
```

Linux (amd64, arm64, armv7), macOS (Intel, Apple silicon) and Windows (amd64, arm64). The installer verifies the release's SHA-256 checksum, installs per user without `sudo` (`~/.local/bin`, Windows `%LOCALAPPDATA%\OTFabric\bin`), and upgrades in place when run again. Pin a version with `OTF_VERSION=x.y.z`; for CI, containers and device images use `OTF_UNMANAGED_INSTALL=<dir>`; all options: [otfabric/install](https://github.com/otfabric/install#options). `OTF_VERSION` is the version of go-mms-trace, which ships `mmstracectl`. For offline machines, the archives and checksums are on [Releases](https://github.com/otfabric/go-mms-trace/releases).

Contributors build it from a checkout with `make build` (`./bin/mmstracectl`).

### Commands

| Command | What it tells you |
|---|---|
| `info CAPTURE...` | format, size, SHA-256, packets, interfaces, time span; counts of associations, transactions by status and service, reports, streams; the counters |
| `associations CAPTURE...` | one row per association: client, server, open, close, accepted, authentication, transactions, reports, unanswered, gaps, first and last time |
| `transactions CAPTURE...` (alias `timeline`) | the confirmed services in time order: time, association, invoke ID, service, status, latency, object; `--service`, `--status`, `--assoc` filter |
| `reports CAPTURE...` | the InformationReports: time, association, list or variables, number of values |
| `goose CAPTURE...` | the GOOSE streams with their issues |
| `sv CAPTURE...` | the Sampled Values streams with lost and repeated samples |
| `version` | version, tag, commit, build date, libraries, Go version and platform |

`--format` is `text` (default), `json` (one document per command) or `csv` (`transactions`, `reports`, `goose`, `sv`). `--port` sets the MMS server ports (default 102). Several captures are analysed one by one; `-` reads standard input. Every flag can be set as `MMSTRACECTL_<FLAG>`. Exit codes: 0 success, 2 usage, 3 invalid input (also a damaged capture, after printing what was read), 10 output or internal error, 130 interrupted. Details: [cmd/mmstracectl/README.md](cmd/mmstracectl/README.md).

```sh
# What is in this capture?
mmstracectl info substation.pcapng

# Every failed or unanswered service of association 3.
mmstracectl transactions substation.pcapng --assoc 3 --status error,reject,unanswered

# The GOOSE streams as CSV.
mmstracectl goose substation.pcapng --format csv > goose.csv
```

### Shell completion

The value sets of `--format` and `--status` complete, and capture arguments complete `.pcap`, `.pcapng`, `.cap` and `.gz` files.

```sh
# bash (needs the bash-completion package)
mkdir -p ~/.local/share/bash-completion/completions
mmstracectl completion bash > ~/.local/share/bash-completion/completions/mmstracectl

# zsh: a directory on your fpath, then restart the shell
mkdir -p ~/.zsh/completions && mmstracectl completion zsh > ~/.zsh/completions/_mmstracectl

# fish
mkdir -p ~/.config/fish/completions && mmstracectl completion fish > ~/.config/fish/completions/mmstracectl.fish
```

```powershell
# PowerShell: add this line to your profile ($PROFILE)
mmstracectl completion powershell | Out-String | Invoke-Expression
```

## Library

```sh
go get github.com/otfabric/go-mms-trace
```

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/otfabric/go-mms-trace/trace"
)

func main() {
	f, err := os.Open("substation.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	res, err := trace.Analyze(context.Background(), f, trace.Options{})
	if err != nil && !errors.Is(err, trace.ErrCorrupt) {
		log.Fatal(err) // not a capture, or cancelled
	}
	for _, t := range res.Transactions {
		fmt.Println(t.Association, t.InvokeID, t.Service, t.Status, t.LatencyNS())
	}
	for _, g := range res.GOOSE {
		fmt.Println(g.GocbRef, g.Messages, g.Issues)
	}
}
```

`trace.Analyze` reads the whole capture and returns a `trace.Result`. A damaged file returns what was read before the damage together with an error wrapping `trace.ErrCorrupt`. The transactions keep the decoded PDUs (`mms.CapturedPDU`) of their request and response. The API is in [API.md](API.md).

## Documentation

| Document | What it covers |
|---|---|
| [API.md](API.md) | The `trace` package |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The pipeline and its limits |
| [ERRORS.md](ERRORS.md) | Errors and counters |
| [LIMITATIONS.md](LIMITATIONS.md) | What is not decoded or not proven yet |
| [SECURITY.md](SECURITY.md) | Reporting, untrusted input |
| [TESTING.md](TESTING.md) | Fixtures, golden files, fuzzing |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup and rules |
| [RELEASE.md](RELEASE.md) | Release notes |
| [cmd/mmstracectl/README.md](cmd/mmstracectl/README.md) | The CLI |

## License

MIT: see [LICENSE](LICENSE).
