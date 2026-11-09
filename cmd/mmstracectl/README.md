# mmstracectl

`mmstracectl` reads packet captures (pcap or pcapng, plain or gzip) and reports the IEC 61850 traffic in them: the MMS associations over ISO-on-TCP with their confirmed services and reports, and the GOOSE and Sampled Values streams. It never captures live and never sends anything: the capture is its only input. It is a nested module of [go-mms-trace](../../README.md), so the library does not depend on cobra.

Install it with the one-line installer: see [Install mmstracectl](../../README.md#install-mmstracectl). Contributors build it from a checkout of go-mms-trace with `make build` (`./bin/mmstracectl`).

During development `go.mod` replaces the library with the checkout (`replace github.com/otfabric/go-mms-trace => ../..`). At release that line is replaced by a version pin of the released library, as `cmd/mbtracectl` pins go-modbus-trace.

## Commands

| Command | What it does |
|---|---|
| `mmstracectl info CAPTURE...` | Summarise each capture: format, size, SHA-256, packets, interfaces, time span; associations, transactions by status and service, reports, GOOSE and SV streams; counters |
| `mmstracectl associations CAPTURE...` | List the MMS associations (alias `assoc`) |
| `mmstracectl transactions CAPTURE...` | List the confirmed services in time order (alias `timeline`) |
| `mmstracectl reports CAPTURE...` | List the InformationReports |
| `mmstracectl goose CAPTURE...` | List the GOOSE streams with their issues |
| `mmstracectl sv CAPTURE...` | List the Sampled Values streams with their issues |
| `mmstracectl version` | Print the version |
| `mmstracectl completion bash\|zsh\|fish\|powershell` | Generate the shell completion script |

A capture argument is a path, or `-` for standard input (alone). Several captures are analysed one by one: text tables get a `==> name <==` line per capture, CSV has a `file` column, JSON a `files` array.

## Flags

| Flag | Commands | Default | Meaning |
|---|---|---|---|
| `--format` | all | `text` | `text` or `json`; also `csv` for `transactions`, `reports`, `goose` and `sv` |
| `--port` | all but `version` | `102` | TCP ports of MMS servers, comma-separated |
| `--max-packet` | all but `version` | `0` | Largest packet record read, bytes (0: 256 KiB) |
| `--service` | `transactions` | | Only these services (`Read`, `Write`, `GetNameList`, ...; any case) |
| `--status` | `transactions` | | Only these statuses: `ok`, `error`, `reject`, `unanswered`, `orphan`, `pending` |
| `--assoc` | `transactions` | | Only these association IDs |
| `-h`, `--help` | all | | Help for the command |

Every flag can also be set by an environment variable: `MMSTRACECTL_` and the flag name in capitals with dashes as underscores (`MMSTRACECTL_FORMAT=json`, `MMSTRACECTL_PORT=102,3782`); a flag on the command line wins.

## Output

Text is a table per capture. Times are UTC: microseconds in text, nanoseconds (fixed width) in CSV, RFC 3339 with nanoseconds in JSON. Object names are written `domain/item` for domain-specific names, `@/item` for association-specific names and `item` for VMD names. The `transactions` object column is the first variable of a Read or Write (`(+n)` for more), `list <name>` for a named variable list, the domain and object class of a GetNameList, or the vendor, model and revision of an Identify response.

`--format json` writes one indented JSON document: [docs/json-output.md](docs/json-output.md). Exit codes: [docs/exitcodes.md](docs/exitcodes.md).

## Examples

```sh
# What is in this capture?
mmstracectl info substation.pcapng

# The associations, as JSON.
mmstracectl associations substation.pcapng --format json

# Every failed or unanswered service of association 3.
mmstracectl transactions substation.pcapng --assoc 3 --status error,reject,unanswered

# Reads and writes only, as CSV.
mmstracectl timeline substation.pcapng --service read,write --format csv

# Reports, GOOSE and SV.
mmstracectl reports substation.pcapng
mmstracectl goose substation.pcapng --format csv
mmstracectl sv substation.pcapng

# MMS on a second port too.
mmstracectl info substation.pcapng --port 102,10102 --max-packet 65536

# Straight from a capture on a gateway.
ssh gw 'tcpdump -i eth0 -U -w - port 102' | mmstracectl transactions -

# The version, as JSON.
mmstracectl version --format json
```
