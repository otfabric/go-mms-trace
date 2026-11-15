# Feature status

What go-mms-trace decodes or derives, and the evidence for each. Levels, from weakest to strongest:

- **Implemented**: code and unit tests on hand-built input.
- **Tested**: exercised end to end through `trace.Analyze` in CI on captures this repository generates from go-mms and go-iec61850 traffic ([TESTING.md](../TESTING.md)).
- **Third-party traffic**: checked in CI on captures of other implementations: the captures between independent stacks (`TestInteropCaptures`) and the public captures held to their recorded summary (`TestPublicCaptures`) ([INTEROPERABILITY.md](../INTEROPERABILITY.md)).
- **Compared with Wireshark**: the same result as Wireshark 4.6.9's dissector on all interop and public captures, for the fields `scripts/compare-wireshark.py` compares, run by hand on 2026-11-10 ([INTEROPERABILITY.md](../INTEROPERABILITY.md#comparison-with-wireshark)); not in CI.

Nothing here is certified or a conformance statement. Gaps are in [LIMITATIONS.md](../LIMITATIONS.md).

## Capture files and lower layers

| Feature | Implemented | Tested | Third-party traffic | Notes |
|---|---|---|---|---|
| pcap, microsecond and nanosecond, both byte orders | yes | yes | yes (public captures) | fuzzed (`FuzzPcapReader`) |
| pcapng: sections, interfaces, enhanced, simple and obsolete packet blocks, timestamp resolution and offset | yes | pcapng unit tests | yes (QUT-ZSS-2023-MMS captures) | fuzzed (`FuzzPcapngReader`); frame numbers and lengths of a generated file cross-checked with tshark when installed (`TestTshark`) |
| gzip input | yes | unit tests in `internal/pcapio`; through `Analyze` in `TestMaxBytes` and `TestErrorChain` | no | no gzip capture among the committed captures |
| Damage handling (`ErrCorrupt` with its cause, truncated tail, skipped blocks, times past the range) | yes | yes (`testdata/damaged.pcap`, `TestErrorChain`, `TestTimeOutOfRange`) | no | |
| Limits on the input as a whole (`Options.MaxBytes`, `MaxInterfaces`, `MaxSections`; `ErrLimit`) | yes | yes (`TestMaxBytes`, `TestInterfaceAndSectionLimits`) | no | each with an allocation budget ([TESTING.md](../TESTING.md#5-limits-and-budgets)) |
| Link types: Ethernet with VLAN tags, Linux cooked v1 and v2, null, loop, raw, raw IPv4 and IPv6 | yes | Ethernet only | Ethernet | the other link types by unit tests in `internal/link`; fuzzed (`FuzzLinkIPTCP`) |
| IPv4 and IPv6, IP fragment reassembly | yes | IPv4; IPv4 fragments (`TestAnalyzeFragments`) | IPv4 | IPv6 and fragments by unit tests in `internal/link`; fragment sequences fuzzed against the reassembly rule (`FuzzDefragSequence`) |
| TCP reassembly: midstream start, gaps, retransmissions, out-of-order, epochs, eviction | yes | yes (gaps, midstream, resets) | yes | the rest by unit tests in `internal/flow`; segment sequences fuzzed (`FuzzSegments`); the tests also run on linux/386 every night |
| Segmentation-offload IPv4 packets (`TSOSegments`) | yes | unit test | yes (ICS-Pcaps ABB and Siemens captures) | |

## ISO stack and MMS

| Feature | Implemented | Tested | Third-party traffic | Compared with Wireshark |
|---|---|---|---|---|
| TPKT framing with resync, COTP (go-cotp), TSDU reassembly from DT TPDUs | yes | yes (split TPDUs, garbage, oversized TSDUs; every frame found after a loss: `TestFramingAfterLoss`; `FuzzFramer`) | yes; leaving out one packet of a capture loses no PDU without bytes in it (`TestOnePacketLoss`, every packet in the nightly run) | indirectly: no compared PDU is missing on either side |
| Session, presentation, ACSE (go-mms `DecodeTSDU`): association open, AARE result, authentication mechanism, release, abort | yes | yes | yes (every interop association is opened, accepted and ended) | no |
| MMS initiate response (`Association.Initiate`) | yes | yes | yes (every interop association has one) | no |
| Confirmed request and response pairing by invoke ID, per direction | yes | yes (`ok`, `error`, `unanswered`, `orphan`, `pending`) | yes | yes: kind, invoke ID and request service |
| Pairs across a capture loss (`uncertain` status) | yes | yes (`TestPairingAcrossLoss`, and 400 seeded scripts with one invoke ID and units left out: `TestPairingNeverCrossesLoss`) | no: no committed capture has such a pair | no |
| Reject PDUs (`reject` status) | yes | no | public captures only (`qut-zss-2023-mms/Action_5.pcapng`); none in the interop captures | yes |
| Server-sent requests (`ServerRequest`, ObtainFile) | yes | yes (`TestPairingAcrossLoss`, the scripts with the requests of the server) | yes (ObtainFile in the interop MMS captures and `adsc-zeek/obtainFile.pcap`) | yes |
| MMS straight in COTP (`BareMMS`) | yes | no | yes (ITI captures) | yes |
| MMS service content: variables, values, name lists, identify, errors (go-mms) | yes, by go-mms | yes, for the services the fixture uses | yes: no `DecodeError` in the interop captures; public captures' decode errors recorded in `expected.json` | no: values, names and error codes are not compared |
| InformationReports | yes | yes | yes (interop reporters, public captures) | by count only |
| MMS over TLS | no | | | |

## GOOSE and Sampled Values

| Feature | Implemented | Tested | Third-party traffic | Compared with Wireshark |
|---|---|---|---|---|
| GOOSE streams and sequencing issues (go-iec61850 `goose.Decode`) | yes | yes (every issue kind, simulation and ndsCom flags, VLAN; stNum and sqNum at the edges of their 32 bits and the rollover of stNum to 1: `TestGooseSequenceBoundaries`) | yes (libiec61850 and cB-Sigma publishers; public captures; none near the rollover) | no |
| Sampled Values streams, lost and repeated samples (go-iec61850 `sv.Decode`) | yes | yes (lost, repeated) | yes (libiec61850 publisher; public captures) | no |
| GOOSE and SV on link types other than Ethernet, routable GOOSE and SV (IEC 61850-90-5) | no | | | |

## mmstracectl

| Feature | Evidence |
|---|---|
| Commands `info`, `associations`, `transactions`, `reports`, `goose`, `sv`, `version`, `completion` | golden outputs of every command and format on the fixtures (`cmd/mmstracectl/golden_test.go`), CI job `cli` |
| Exit codes 0, 2, 3, 10, 130 | `TestExitCodes`, `TestExitCode`, `TestWriteErrors`, `TestInterrupted` in `cmd/mmstracectl/main_test.go` |
| `MMSTRACECTL_*` environment variables, filters, other ports, standard input | `TestEnvironment`, `TestFilters`, `TestOtherPorts`, `TestStdin` |
| `--max-bytes`: a capture past the limit is printed up to it, then exit 3 | `TestMaxBytesFlag` |
| Names of a capture written as printable text in text and CSV output, and escaped in JSON | `TestPrintable`, `TestTextAndCSVArePrintable` (every command and format on a result whose names hold control characters), `TestControlCharactersOfACapture` (from a capture to the output) |
| Same numbers as the library | `TestCLIEqualsLibrary` |
| Platforms: linux/amd64, linux/arm64, darwin/arm64, darwin/amd64, windows/amd64, windows/arm64 built and tested; linux/arm (v7) built only; the tests of both modules run on linux/386 every night | `targets` job in `.github/workflows/ci.yml`; `test-386` job in `.github/workflows/nightly.yml` |
