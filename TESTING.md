# Testing

```sh
make test       # race tests, library and cmd/mmstracectl
make check      # format, mod check, lint, vet, vulnerability scan, tests, coverage gates, cross-builds, docsync
make fuzz       # every fuzz target for FUZZ_TIME (default 30s)
make golden     # regenerate the fixtures and the CLI's golden outputs
```

`make test` needs no privileges and no network beyond the loopback: the tests run go-mms clients and servers on 127.0.0.1, and every capture they read is in the repository. Optional tools:

| Tool | Used by | Without it |
|---|---|---|
| `tshark` | `TestTshark` (`internal/pcapio`) cross-checks frame numbers and lengths of a generated pcapng file; `make compare-wireshark` | `TestTshark` is skipped; `make compare-wireshark` fails |
| Python 3 | `make compare-wireshark` (`scripts/compare-wireshark.py`) | |
| Docker and the iec61850-interop images | `make record-interop` (`scripts/record-interop.sh`) | |

## 1. Captures in tests

`trace/gen_test.go` builds captures from real MMS traffic:

1. `recordAssociation` starts a go-mms server and connects a go-mms client to it over TCP on 127.0.0.1 (`transport/iso`), runs a piece of client work, and records every unit the client sent and received with go-mms's `RawHook`. `recordReport` does the same for a server that sends an InformationReport.
2. The `capture` type frames those units into a classic pcap: COTP DT TPDUs (split in two when asked), TPKT, TCP with consistent sequence numbers, IPv4 and Ethernet, plus the TCP and COTP handshakes. Losses, orphans, garbage, resets and oversized TSDUs are made by dropping or editing units.
3. GOOSE and SV frames are encoded with go-iec61850's `goose.Encode` and `sv.Encode`.

Both ends of these captures are OT Fabric code (go-mms, go-iec61850): they test this library's pipeline, not its agreement with other implementations, which is in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## 2. Fixtures

| File | What it is |
|---|---|
| `testdata/substation.pcap` | Four associations (complete with Identify, Read, Write, GetNameList, a failing FileDelete and Conclude; one that receives an InformationReport and aborts; one captured midstream with a lost response, an orphan response and a reset; one still waiting at the end), a GOOSE stream and an SV stream with sequencing issues, one TCP segment on another port. |
| `testdata/damaged.pcap` | The same capture with the eleventh record's captured length made impossible: reading ends with `ErrCorrupt` after ten packets. |

Both are written by `TestFixture` in `trace/fixture_test.go` (`go test ./trace -run TestFixture -update`, or `make golden`). Without `-update`, `TestFixture` checks what `Analyze` finds in the committed files; it does not rebuild them. Regenerating them with go-mms v1.7.1 and go-iec61850 v1.15.2 gave the committed bytes (checked 2026-11-10).

`testdata/captures/interop` (captures between independent stacks, `TestInteropCaptures`) and `testdata/captures/public` (public captures, `TestPublicCaptures`) are described, with what their tests check, in [INTEROPERABILITY.md](INTEROPERABILITY.md).

## 3. Golden outputs

`cmd/mmstracectl/golden_test.go` runs every command and format on the fixtures and compares stdout byte for byte with `cmd/mmstracectl/testdata/golden/`. `go test -run TestGolden -update` in `cmd/mmstracectl` rewrites them; review the diff. Line endings are LF everywhere (`.gitattributes`).

## 4. Fuzzing

| Target | Package | Input |
|---|---|---|
| `FuzzPcapReader` | `internal/pcapio` | arbitrary bytes, seeded with two pcap files the tests write (microseconds little-endian, nanoseconds big-endian) |
| `FuzzPcapngReader` | `internal/pcapio` | arbitrary bytes, seeded with pcapng files the tests write (both byte orders) |
| `FuzzLinkIPTCP` | `internal/link` | a link type and a frame |
| `FuzzAnalyze` | `trace` | arbitrary bytes into `Analyze`, seeded with the fixtures and their first halves |

`make fuzz` runs each for `FUZZ_TIME`. CI runs every discovered target for 30 s (`fuzz-time` in `.github/workflows/ci.yml`, the `Fuzz smoke` job of the reusable `go-ci.yml`) and uploads failing inputs as the `fuzz-failures` artifact. A failing input goes into `<package>/testdata/fuzz/<Target>/` with the fix, so that `go test` replays it from then on; there are no such regression inputs yet.

## 5. Coverage

`make coverage-check` requires 90 % in total and `make coverage-pkg-check` 85 % per package, both over the library with `-coverpkg=./...`; CI runs the same gates (`coverage-min` and the `Per-package coverage` job in `ci.yml`). The CLI module's CI job (`cli` in `ci.yml`) requires 90 % of `cmd/mmstracectl`; no make target checks it locally. No package is excluded.

## 6. CI

`.github/workflows/ci.yml` runs on every push and pull request that changes more than Markdown: the organisation's `go-ci.yml` (v3.3.0) for the library and for `cmd/mmstracectl` (golangci-lint, go vet, govulncheck, tests and race tests on Go 1.26 and 1.27, coverage, fuzz smoke for the library, the policy check), and a build and test on each target in its own runner (linux/arm v7 is cross-compiled only, not run), with a static-binary check on Linux. `.github/workflows/docs.yml` runs docsync on every pull request, Markdown-only included. `make compare-wireshark` and `make record-interop` are not run in CI.
