# Testing

```sh
make test       # race tests, library and cmd/mmstracectl
make check      # format, lint, vet, vulnerability scan, tests, coverage gates, cross-builds, docsync
make fuzz       # every fuzz target for FUZZ_TIME (default 30s)
make golden     # regenerate the fixtures and the CLI's golden outputs
```

No privileges, no network beyond the loopback and no real captures are needed.

## 1. Captures in tests

`trace/gen_test.go` builds captures from real MMS traffic:

1. `recordAssociation` starts a go-mms server and connects a go-mms client to it over TCP on 127.0.0.1 (`transport/iso`), runs a piece of client work, and records every unit the client sent and received with go-mms's `RawHook`. `recordReport` does the same for a server that broadcasts an InformationReport.
2. The `capture` type frames those units into a classic pcap: COTP DT TPDUs (split in two when asked), TPKT, TCP with consistent sequence numbers, IPv4 and Ethernet, plus the TCP and COTP handshakes. Losses, orphans, garbage, resets and oversized TSDUs are made by dropping or editing units.
3. GOOSE and SV frames are encoded with go-iec61850's `goose.Encode` and `sv.Encode`.

## 2. Fixtures

| File | What it is |
|---|---|
| `testdata/substation.pcap` | Four associations (complete with Identify, Read, Write, GetNameList, a failing FileDelete and Conclude; one that receives an InformationReport and aborts; one captured midstream with a lost response, an orphan response and a reset; one still waiting at the end), a GOOSE stream and an SV stream with sequencing issues, one TCP segment on another port. |
| `testdata/damaged.pcap` | The same capture with the eleventh record's captured length made impossible: reading ends with `ErrCorrupt` after ten packets. |

Both are written by `TestFixture` in `trace/fixture_test.go` (`go test ./trace -run TestFixture -update`, or `make golden`). The generator is deterministic: the same go-mms version gives the same bytes. Without `-update`, `TestFixture` checks what `Analyze` finds in the committed files.

### Captures between independent stacks

`testdata/captures/interop` holds 12 captures recorded on 2026-11-09 with `scripts/record-interop.sh` from the pinned images of otfabric/iec61850-interop v1.4.0 (contract 1.3), with no OT Fabric code on either end: the full MMS service sequence (identify, name lists, reads and writes of every type, named variable lists, files, journals, InformationReport, negative cases, release and abort) between libiec61850, dscsystems and iec61850-rust; IEC 61850 client, reporter (general interrogation) and controller sequences between libiec61850, iec61850bean, dscsystems, iec61850-rust and cB-Sigma; GOOSE publishers of libiec61850 and cB-Sigma (one state change); the Sampled Values publisher of libiec61850 (9-2LE, 4,000 samples/s, 3.6 s). MMS runs on TCP 1102, the port of the images. `manifest.json` records each file's peers, image digests, licences and checksum (also in `SHA256SUMS`); the `.client.jsonl` files are the clients' own logs of their operations. `TestInteropCaptures` checks the checksums and that every frame decodes, every request is answered (`ok`, or `error` for the fixture's deliberate negative cases), every association associates, is accepted and ends, the reporters receive their report, and the GOOSE and SV streams have no issues. The captures are recordings of protocol traffic, not code of the stacks.

### Public captures

`testdata/captures/public` holds 75 public captures (11 MB) from four sources, pinned by source commit and checksum in `manifest.json`, with their licences in `NOTICE.md`: the ADSC MMS parser traces for Zeek (one capture per MMS service and its optional fields, libIEC61850 v1.4.0 and the EPIC testbed), ITI ICS-Security-Tools (community captures from pcapr.net, several hand-crafted: MMS straight in COTP, responses without a service, malformed association accepts), QUT-ZSS-2023-MMS (a simulated zone substation, several IEDs and an HMI) and EmreEkin/ICS-Pcaps, the ICS Defense archive (among them MMS sessions with ABB and Siemens IEDs, an OMICRON IEDScout session, GOOSE and SV). Six files were left out: four byte-identical duplicates, Wireshark's `mms.pcap.gz` (identical to an ITI capture) and one JSON text named `.pcap` (`manifest.json`, `excluded`). `TestPublicCaptures` checks the checksums and holds every capture to its summary in `expected.json` (associations, statuses, services, reports, streams, counters; `-update` rewrites it).

### Comparison with Wireshark

`make compare-wireshark` (needs tshark) runs `scripts/compare-wireshark.py` over the interop and public captures: per capture, the MMS PDUs mmstracectl decodes and those tshark's dissector decodes, as (kind, invoke ID, service of a request), must be the same. PDUs of associations captured midstream are counted but not compared, since Wireshark needs the association to dissect MMS. On 2026-11-09 with Wireshark 4.6.9 all 86 captures with readable data are the same. The comparison found, and these are fixed: IPv4 packets with a total length of 0 (segmentation offload, in the ABB and Siemens captures) were dropped; invoke IDs were paired across both directions (a server's requests during ObtainFile); MMS straight in COTP was not decoded; and in go-mms v1.7.0 unimplemented services were named `Unknown`, a response without a service was an error, and a GetVariableAccessAttributes response with a primitive address did not decode.

## 3. Golden outputs

`cmd/mmstracectl/golden_test.go` runs every command and format on the fixtures and compares stdout byte for byte with `cmd/mmstracectl/testdata/golden/`. `go test -run TestGolden -update` in `cmd/mmstracectl` rewrites them; review the diff. Line endings are LF everywhere (`.gitattributes`).

## 4. Fuzzing

| Target | Package | Input |
|---|---|---|
| `FuzzPcapReader` | `internal/pcapio` | arbitrary bytes, seeded with pcap files |
| `FuzzPcapngReader` | `internal/pcapio` | arbitrary bytes, seeded with pcapng files |
| `FuzzLinkIPTCP` | `internal/link` | a link type and a frame |
| `FuzzAnalyze` | `trace` | arbitrary bytes into `Analyze`, seeded with the fixtures |

CI runs each for 30 s (`fuzz-time` in `.github/workflows/ci.yml`).

## 5. Coverage

`make coverage-check` requires 90 % in total and `make coverage-pkg-check` 85 % per package (`go test -coverpkg=./...`). The CLI module's CI job requires 90 %.
