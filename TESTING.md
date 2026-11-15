# Testing

```sh
make test       # race tests, library and cmd/mmstracectl
make check      # format, mod check, lint, vet, vulnerability scan, tests, coverage gates, cross-builds, docsync
make fuzz       # every fuzz target for FUZZ_TIME (default 30s)
make bench      # every benchmark
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

Every stage has a target. The readers and `Analyze` take arbitrary bytes; the stages that keep state between packets take a sequence of steps decoded from the input, so that the fuzzer reaches the states only several packets together make.

| Target | Package | Input | What it holds the code to |
|---|---|---|---|
| `FuzzPcapReader` | `internal/pcapio` | arbitrary bytes, seeded with two pcap files the tests write (microseconds little-endian, nanoseconds big-endian) | every packet within the limits and inside the bytes read; the interfaces, sections and text kept within their limits; a second pass with a limit of half the bytes gives the same packets up to it, reads nothing past it and ends with `ErrLimit` |
| `FuzzPcapngReader` | `internal/pcapio` | arbitrary bytes, seeded with pcapng files the tests write (both byte orders, several sections and interfaces) | the same |
| `FuzzLinkIPTCP` | `internal/link` | a link type and a frame | the payload is where its offset says |
| `FuzzDefragSequence` | `internal/link` | a sequence of fragments of four datagrams: offset, length, last or not, from the first to the last offset a datagram can have | after every fragment the bytes charged are those held, within the budget; a datagram that comes out has the length its last fragment gave and, byte for byte, the content the rule gives (the lowest offset, then the first to arrive) |
| `FuzzSegments` | `internal/flow` | a sequence of TCP segments of four connections with small limits: SYN, FIN, RST, sequence numbers around the wrap, acknowledgements, bytes cut by the snap length | after every segment the accounting adds up and is within the limits, and the connections that hold bytes are the heap's; every direction gets its bytes once and in order, every hole at its size; nothing is held at the end and every connection was closed once |
| `FuzzFramer` | `trace` | for two connections, a script of PDUs delivered in pieces of any size, with holes and with bytes of the input in between; a large or a small assembly budget | after every step what the directions hold is what is charged, within the budget, and no more than a frame and a TSDU can be; a direction that got its script whole yields every PDU of it; nothing is charged at the end |
| `FuzzAnalyze` | `trace` | arbitrary bytes into `Analyze`, seeded with the fixtures, their first halves and their gzip form | a result exactly when the error is nil or wraps `ErrCorrupt` or `ErrLimit`; the result adds up (statuses, counts per association); no more of the capture read than the limit |

`make fuzz` runs each for `FUZZ_TIME`. CI runs every discovered target for 30 s on pull requests (`fuzz-time` in `.github/workflows/ci.yml`, the `Fuzz smoke` job of the reusable `go-ci.yml`) and for 5 minutes every night (`.github/workflows/nightly.yml`), and uploads failing inputs as an artifact. A failing input goes into `<package>/testdata/fuzz/<Target>/` with the fix, so that `go test` replays it from then on; there are no such regression inputs yet.

## 5. Limits and budgets

A fuzz run that finds nothing says nothing about memory or work, so every limit of [ARCHITECTURE.md](ARCHITECTURE.md#2-limits) has a test that measures one of them against a budget derived from the limit: bytes allocated (`runtime.MemStats.TotalAlloc` around the call), live heap after a collection, or steps counted by the code. None of them measures time.

| Limit | Test | What is measured |
|---|---|---|
| Capture read (`Options.MaxBytes`) | `TestMaxBytes` (`trace`); `TestMaxBytes` (`internal/pcapio`) | the live heap of the result of a capture of eight times the limit, plain and gzip, against 30 times the limit; the bytes read, at the limit and one byte on either side of it, of the last record and of a cut-short tail |
| Packet record, pcapng block (`Options.MaxPacket`, 16 MiB) | `TestSizeLimits`, `TestMaxPacketRange`, `TestLargeRecords` (`internal/pcapio`) | the bytes allocated for inputs of 12 to 82 bytes that declare records, blocks and section headers at the limits, one past them, of 1 GiB and of the largest length: under 1 MiB, the reader's fixed buffers; every value of `MaxPacket` an `int` can have |
| pcapng interfaces, sections, option text | `TestInterfaceLimit`, `TestSectionLimit`, `TestTextLimit`, `TestOptionsAreaLimit`, `TestMetadataBudget` (`internal/pcapio`); `TestInterfaceAndSectionLimits` (`trace`) | the limit, one below, one above and far above, at the defaults too; the live heap of the reader after 40 times the limits |
| IP fragment reassembly | `TestFragmentBudgetHeap`, `FuzzDefragSequence` (`internal/link`) | the live heap after 150,000 fragments (many datagrams, datagrams of the most fragments, one offset again and again) against three times the budget; the bytes charged after every fragment |
| IPv6 extension headers | `TestDecode` (`internal/link`) | the count: a ninth header ends the walk |
| Tracked TCP connections | `TestConnectionLimitHeap` (`trace`, the default through `Analyze`); `TestEviction` (`internal/flow`) | the live heap at the end of a pass over 250,000 connections against 1.5 KiB for each of the 100,000 tracked |
| Out-of-order bytes per direction | `TestOverflowAndBudget`, `FuzzSegments` (`internal/flow`) | the bytes charged to a direction after every segment, against its limit (at the default at most 8,192 held segments) |
| Out-of-order bytes in total | `TestBufferBudgetHeap`, `TestBudgetWork`, `TestBudgetVictim` (`internal/flow`) | the live heap of 102,400 held segments against three times the budget; the steps to choose the connection that gives up a hole, counted: the same with 1,000 and with 20,000 connections tracked, and within a bound that depends only on the connections that hold bytes |
| TSDU (`MaxTSDU`) | `TestTSDULimitHeap` (`trace`, the default through `Analyze`); `TestAnalyzeStreamsAndStack` | the live heap when the input of a TSDU of 17 MiB ends: under 2 MiB, nothing of the TSDU |
| Incomplete frames and TSDUs (`Options.MaxAssembly`) | `TestAssemblyBudgetHeap`, `TestAssemblyBudget` (`trace`) | the live heap of 2,000 directions fed 96 MiB with a budget of 1 MiB; which directions give up and what is counted |
| The scratch of a GOOSE stream | `TestGooseKeepsNoScratch` (`trace`) | the live heap of the result of 20,000 messages: under 64 KiB |

The other numeric boundaries have tables of their own: `TestPcapNGTimestampRange` and `TestTimeOutOfRange` (the first and the last time that fits, for four resolutions and offsets of both signs), `TestOldSegmentDistances` (TCP sequence distances up to 2^32-1, which matter where an `int` has 32 bits), `TestDefragLastFragment` (the last fragment against the fragments held, both orders, the largest datagram), `TestGooseSequenceBoundaries` (stNum and sqNum at 0, 1, 2^32-2, 2^32-1 and the rollover). The tests run on linux/386 every night.

Three properties are checked on generated or committed captures rather than on one input:

- `TestPairingNeverCrossesLoss`: 400 seeded scripts of exchanges that all use one invoke ID, with units left out at random; no transaction with a certain status pairs a request with the answer to another. A failure prints its seed.
- `TestFramingAfterLoss`: every frame after a loss is found, with bytes in between that read as TPKT headers.
- `TestOnePacketLoss`: in the 87 committed captures of other implementations, leaving out one packet never loses more PDUs than have bytes in it. A pull request leaves out the packets of `lossSensitive` and a few others of each capture; `MMSTRACE_ALL_PACKETS=1` (the nightly workflow) leaves out every packet in turn, about 3 minutes.

## 6. Contract tests

The library has one entry point, `trace.Analyze`: synchronous, in the caller's goroutine, with no goroutines of its own, no `Close`, no callbacks and no network. The rows of the organisation's contract test matrix (otfabric/engineering `standards/lifecycle.md`) that apply:

| Row | Applies | Test |
|---|---|---|
| L1, L2 Close twice, concurrent Close | n/a: no type with `Close`; `Analyze` does not close its reader | |
| L3 to L5 Close during a read, a write, a handshake | n/a: offline; nothing to close, nothing written, no handshake | |
| L6 Cancel a pending operation | yes | `TestCancel`: `context.Canceled` and no result, before the first packet and in the middle of the pass, and the reader is not read further; a deadline that has passed. `TestInterrupted` (`cmd/mmstracectl`): exit 130 |
| L7, L8, L16 Late response, reconnect | n/a: no client | |
| L9 to L11 Callbacks | n/a: no public callback or hook ([OBSERVABILITY.md](OBSERVABILITY.md)) | |
| L12 Bounded queues at capacity | yes | section 5: every limit, with the default limits through `Analyze` for the connection, TSDU, interface and section limits |
| L13 Concurrent sessions | yes | `TestConcurrentAnalyze`: 16 goroutines, 20 passes each over different captures and options, under the race detector; every result is the one a call by itself returns |
| L14 Failure during startup | yes | `TestErrorChain`: a reader that fails at its first byte, inside the file header and inside the gzip stream returns no result and an error that wraps `ErrFormat` and the reader's error; nothing is acquired before the format is known |
| L15 `Shutdown(ctx)` | n/a | |

Ownership (otfabric/engineering `standards/safety.md`, SAFE-R02) is tested the same way: `TestResultIsOwned` overwrites the input after the call and everything reachable from the result, and compares the next result with the first; `TestDataIsNotKept` overwrites the bytes the TCP stage delivers after every call.

## 7. Benchmarks

`make bench` runs them; the nightly workflow runs one iteration of each, so that a benchmark that fails is found. No figure is compared or gated in CI, and no document states a performance figure other than the memory measurements of [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md#2-limits).

| Benchmark | Package | What it measures |
|---|---|---|
| `BenchmarkAnalyze` | `trace` | a whole pass, per byte of input: the fixture, 20,000 Read exchanges (plain and gzip), 96,000 requests packed 24 to a segment, 20,000 GOOSE messages |
| `BenchmarkReader` | `internal/pcapio` | reading 20,000 packets: pcap, pcapng, pcap as gzip |
| `BenchmarkTracker` | `internal/flow` | the TCP stage on decoded segments: in order, out of order, and with the total out-of-order budget full |

To compare two revisions, use the organisation's procedure (otfabric/engineering `standards/performance.md`): both builds on the same machine, interleaved, with `benchstat`.

## 8. Coverage

`make coverage-check` requires 90 % in total and `make coverage-pkg-check` 85 % per package, both over the library with `-coverpkg=./...`; CI runs the same gates (`coverage-min` and the `Per-package coverage` job in `ci.yml`). The CLI module's CI job (`cli` in `ci.yml`) requires 90 % of `cmd/mmstracectl`; no make target checks it locally. No package is excluded.

## 9. CI

`.github/workflows/pr.yml` calls `.github/workflows/ci.yml` on every pull request that changes more than Markdown: the organisation's `go-ci.yml` (v3.8.0) for the library and for `cmd/mmstracectl` (golangci-lint, go vet, govulncheck, tests and race tests on Go 1.26 and 1.27, coverage, fuzz smoke for the library), and a build and test on each target in its own runner (linux/arm v7 is cross-compiled only, not run), with a static-binary check on Linux. `.github/workflows/docs.yml` runs docsync and otfabric-policy on every pull request, Markdown-only included, and on every push to `main`. `.github/workflows/nightly.yml` runs every night and on dispatch: every fuzz target for 5 minutes, the tests of both modules on linux/386 (an `int` of 32 bits, as on linux/arm v7; without the race detector, which 386 does not have), `TestOnePacketLoss` over every packet, and one iteration of every benchmark. `make compare-wireshark` and `make record-interop` are not run in CI.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Every night, or dispatch | `nightly.yml` | long fuzzing, the tests on linux/386, the one-packet-loss property over every packet, the benchmarks once |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
