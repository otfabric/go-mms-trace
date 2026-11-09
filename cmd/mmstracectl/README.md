# mmstracectl

`mmstracectl` reads packet captures (pcap or pcapng, plain or gzip) and reports the IEC 61850 traffic in them: the MMS associations over ISO-on-TCP with their confirmed services and reports, and the GOOSE and Sampled Values streams. It never captures live and never sends anything: the capture is its only input. It is a nested module of [go-mms-trace](../../README.md), so the library does not depend on cobra.

Install it with the one-line installer: see [Install mmstracectl](../../README.md#install-mmstracectl). Contributors build it from a checkout of go-mms-trace with `make build` (`./bin/mmstracectl`).

`go.mod` pins a released version of the library, as `cmd/mbtracectl` pins go-modbus-trace, so a release of the CLI builds on a released library. To work on both at once, use a `go.work` in the checkout (git-ignored).

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

A capture argument is a path, or `-` for standard input (alone). Several captures are analysed one by one, and all of them are read before anything is written: `info` text starts each capture with its `file` line, the other text tables get a `==> name <==` line per capture, CSV has a `file` column, JSON a `files` array. A capture that cannot be opened or is not a capture stops the command before any output; a damaged one is reported with what was read before the damage ([docs/exitcodes.md](docs/exitcodes.md)).

## Flags

| Flag | Commands | Default | Meaning |
|---|---|---|---|
| `--format` | all | `text` | `text` or `json`; also `csv` for `transactions`, `reports`, `goose` and `sv` |
| `--port` | all but `version` | `102` | TCP ports of MMS servers, comma-separated (1 to 65535, at least one) |
| `--max-packet` | all but `version` | `0` | Largest packet record read, bytes (0: 256 KiB; negative is a usage error) |
| `--service` | `transactions` | | Only these services (`Read`, `Write`, `GetNameList`, ...; any case) |
| `--status` | `transactions` | | Only these statuses: `ok`, `error`, `reject`, `unanswered`, `orphan`, `pending` |
| `--assoc` | `transactions` | | Only these association IDs (from 1) |
| `-h`, `--help` | all | | Help for the command |

Every flag can also be set by an environment variable: `MMSTRACECTL_` and the flag name in capitals with dashes as underscores (`MMSTRACECTL_FORMAT=json`, `MMSTRACECTL_PORT=102,3782`); a flag on the command line wins.

## Output

Text is a table per capture. Times are UTC: microseconds in text, nanoseconds (fixed width) in CSV, RFC 3339 with up to nine fractional digits in JSON; a missing time is `-` in text and empty in CSV. CSV starts with a header row; the `transactions` CSV has the class and code of a confirmed error but not the fields of a reject (use JSON). Object names are written `domain/item` for domain-specific names, `@/item` for association-specific names and `item` for VMD names. The `transactions` object column is taken from the request (from the response of an orphan): the first variable of a Read or Write (`(+n)` for more), `list <name>` for a named variable list, the variable of a GetVariableAccessAttributes request, `class <n> in <domain>` (or `class <n> (<scope>)`) for a GetNameList, or the vendor, model and revision of an Identify response.

`--format json` writes one indented JSON document: [docs/json-output.md](docs/json-output.md). Exit codes: [docs/exitcodes.md](docs/exitcodes.md).

## Examples

```sh
# Run from a go-mms-trace checkout: testdata/substation.pcap is the generated fixture.

# What is in this capture?
mmstracectl info testdata/substation.pcap

# The associations, as JSON.
mmstracectl associations testdata/substation.pcap --format json

# Every failed or unanswered service of association 3.
mmstracectl transactions testdata/substation.pcap --assoc 3 --status error,reject,unanswered

# Reads and writes only, as CSV.
mmstracectl timeline testdata/substation.pcap --service read,write --format csv

# Reports, GOOSE and SV.
mmstracectl reports testdata/substation.pcap
mmstracectl goose testdata/substation.pcap --format csv
mmstracectl sv testdata/substation.pcap

# MMS on a second port too.
mmstracectl info testdata/substation.pcap --port 102,10102 --max-packet 65536

# From a capture on a gateway: output starts when tcpdump stops (here after 10000 packets).
ssh gw 'tcpdump -i eth0 -c 10000 -U -w - port 102' | mmstracectl transactions -

# The version, as JSON.
mmstracectl version --format json
```
