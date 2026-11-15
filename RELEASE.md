# go-mms-trace Releases

## v0.4.0

**Date:** 2026-11-14
**Previous release:** v0.3.7

The analysis takes what a capture lost into account when it frames and pairs, bounds the input as a whole, and keeps the cause of a read error in the error it returns. The exported API grows: `Options.MaxBytes`, `Options.MaxInterfaces`, `Options.MaxSections` and `Options.MaxAssembly` with their `Default…` constants, `ErrLimit`, `StatusUncertain`, `File.UncompressedBytes` and `File.BadTimestamps`. Nothing exported is removed or changed.

### Breaking

No exported identifier breaks. The behaviour below changes; each entry says how to keep the previous behaviour where that is possible.

- **A response paired across a capture loss has the status `uncertain`.** A response is paired with the held request of its invoke ID as `ok`, `error` or `reject` only when the capture holds everything the two sides sent between the two. It is `uncertain` (`StatusUncertain`) when bytes or PDUs of the requesting direction were lost in between, or the responder had acknowledged bytes of the requester that the capture does not hold, or bytes of the responding direction were lost that the requester had not acknowledged when it sent the request: the response may then answer a later request with the same invoke ID that was not captured (API.md, ARCHITECTURE.md section 5). `Request`, `Response`, the times and the frames are set as before. Code that switches on `Transaction.Status` sees a seventh value. To classify as before: map `uncertain` by `Response.Kind` (`confirmed-response` to `ok`, `confirmed-error` to `error`, `reject` to `reject`). None of the committed captures has such a pair.
- **The capture read is bounded: 16 GiB, counted after decompression** (`Options.MaxBytes`, `DefaultMaxBytes`). A capture that goes on past it ends the analysis with the result so far and an error wrapping the new `ErrLimit`, which is not `ErrCorrupt`. To read without a bound: `Options{MaxBytes: math.MaxInt64}`.
- **A pcapng input is bounded to 65,536 interfaces and 65,536 sections** (`Options.MaxInterfaces`, `Options.MaxSections`). A further interface is skipped with the packets captured on it (`File.SkippedBlocks`); a further section ends the analysis with `ErrLimit`. To read without these bounds: set both to `math.MaxInt`. The reader also keeps at most 16 MiB of interface and section option text, which the `Result` never held.
- **Incomplete TPKT frames and TSDUs are bounded to 64 MiB over all connections** (`Options.MaxAssembly`). Beyond it the direction that has waited longest gives up what it holds: its TSDU counts in `TSDUErrors`, the bytes of its frame in `TPKTResync`. To hold without this bound: `Options{MaxAssembly: math.MaxInt}`. A TSDU that passes `MaxTSDU` is let go when it passes the limit and counted when it ends, as before.
- **TPKT framing where a direction is not synchronised** (after a gap, after bytes that are no TPKT header, at the start of a stream captured from its middle): a TPKT header is accepted when the COTP TPDU behind it decodes, and otherwise costs one byte, so that a frame inside the bytes it claims is found. On such captures PDUs are found that were passed over, `Counters.TPKTResync` is higher and `Counters.COTPErrors` lower: `COTPErrors` now counts frames of a synchronised direction only. Of the committed captures, 16 public ones (the ITI "MMS specific commands") change in these two counters only (for example `cotp_errors` 2 to 0, `tpkt_resync` 17 to 36); no association, transaction or report of any committed capture changes. There is no option for the previous framing.
- **GOOSE state numbers at the top of their range**: retransmissions of the state with stNum 4294967295 are no state change, and the step from 4294967295 to 1 is one (`Changes`), not `stNum decreased`. Streams that do not reach that number are reported as before.
- **A pcapng time that does not fit in 64 bits of nanoseconds** (after 2262-04-11 or before 1677-09-21, with the interface's resolution and offset) leaves its packet without a time, counted in `File.BadTimestamps`; its transactions and reports have time 0.
- **IP fragments**: every fragment of a datagram lies within the length its last fragment gives. A last fragment that ends before fragments already held is counted as `fragment_bad`, and its datagram is given up.

### Added

- `Options.MaxBytes`, `Options.MaxInterfaces`, `Options.MaxSections`, `Options.MaxAssembly`; `DefaultMaxBytes`, `DefaultMaxInterfaces`, `DefaultMaxSections`, `DefaultMaxAssembly`; `ErrLimit`; `StatusUncertain`; `File.UncompressedBytes` (the size of the capture as read, after decompression) and `File.BadTimestamps`.
- A limits table with the reason for each default, the bytes the pipeline holds when every limit is reached, and the work a packet costs (ARCHITECTURE.md section 2); the memory a result takes for each byte of capture, measured (SECURITY.md).
- Fuzz targets for the stages that keep state between packets, fed with sequences: `FuzzDefragSequence` (IP fragments, checked against the reassembly rule), `FuzzSegments` (TCP segments), `FuzzFramer` (the ISO framing with pieces, holes and other bytes). `FuzzAnalyze` and the reader targets check what they return.
- A test for every limit that measures allocation, live heap or counted steps against a budget, boundary tables for the numeric fields, the contract test matrix, and benchmarks of `Analyze`, the reader and the TCP stage (TESTING.md sections 5 to 7).
- A nightly workflow: every fuzz target for 5 minutes, the tests of both modules on linux/386, `TestOnePacketLoss` over every packet of the committed captures, the benchmarks once.

### Changed

- go-mms v1.11.0 (was v1.10.0) and go-iec61850 v1.23.0 (was v1.22.0). The decoding of captures is unchanged: the new releases change servers, clients and the ISO transport, which this module does not use, and every committed capture gives the same result.
- The error of `Analyze` keeps its cause: an error wrapping `ErrCorrupt` also wraps what the reader reported (the error of the caller's `io.Reader`, `gzip.ErrChecksum`), and a read error before the format is known wraps `ErrFormat` and that error. More `errors.Is` matches; none is removed. ERRORS.md says when an error is worth another read.
- `Options.MaxPacket` above the 32 bits a record length has bounds nothing (the reader takes it as the largest length).
- The caller owns the `Result` and everything reachable from it (API.md): `Association.CallingTSAP` and `CalledTSAP` are copies.
- Memory and work: a record or block is read in steps, so a length the input does not hold is not allocated; a held TCP segment is let go when it is delivered; the scratch of a GOOSE stream (every pair of numbers seen, a count per second) is let go before `Analyze` returns; the connection that gives up a hole at the total out-of-order budget is chosen in a number of steps that does not depend on the connections tracked; TCP sequence distances are compared as 32-bit numbers on every platform.
- AGENTS.md names the otfabric-policy version CI runs (v1.6.1).

---

## v0.3.7

**Date:** 2026-11-14
**Previous release:** v0.3.6

No API change.

### Changed

- go-mms v1.10.0 (was v1.9.3), go-iec61850 v1.22.0 (was v1.20.2), go-cotp v1.4.1 (was v1.3.0) and go-tpkt v1.2.1 (was v1.1.0). Decoding is stricter: go-mms v1.10.0 decodes Data to at most 64 nesting levels, limits a Write request's listOfData to 65,536 elements and refuses an object identifier subidentifier with a leading 0x80 octet, and go-iec61850 v1.22.0 refuses an SV `svID` or `datSet` longer than 129 octets. A TSDU or SV frame outside these bounds is now counted in `TSDUErrors` or `SVErrors`; the server, client and SCL limits of the new releases are not used by this module.
- `mmstracectl` is built on go-mms-trace v0.3.5, go-mms v1.10.0 and go-iec61850 v1.22.0.

---

## v0.3.6

**Date:** 2026-11-14
**Previous release:** v0.3.5

No API change.

### Changed

- go-mms v1.9.3 (was v1.9.2) and go-iec61850 v1.20.2 (was v1.20.1). go-mms v1.9.3 bounds counts, indexes and REAL exponents when they are decoded (go-mms RELEASE.md, v1.9.3); the go-iec61850 library code is unchanged.
- `mmstracectl` is built on go-mms-trace v0.3.5, go-mms v1.9.3 and go-iec61850 v1.20.2.

---

## v0.3.5

**Date:** 2026-11-14
**Previous release:** v0.3.4

No API change.

### Changed

- go-iec61850 v1.20.1 (was v1.19.4). v1.20.0 added the sender address of R-GOOSE and R-SV frames (`rsession.Transport.RecvFrom`); the library code of v1.20.1 is the same as v1.20.0.
- `mmstracectl` is built on go-mms-trace v0.3.4 (was v0.3.3), go-mms v1.9.2 and go-iec61850 v1.20.1.
- CI: otfabric/engineering policy 1.6 and the shared workflows v3.8.0. Releases now run the API compatibility gate before tagging.

---

## v0.3.4

**Date:** 2026-11-12
**Previous release:** v0.3.3

No API change.

### Changed

- go-mms v1.9.2 and go-iec61850 v1.19.4 (were v1.9.1 and v1.19.1). go-mms v1.9.2 makes the `iso.WithDialer` dialer follow the `net.Dialer` contract.
- `mmstracectl` is built on go-mms-trace v0.3.3, go-mms v1.9.2 and go-iec61850 v1.19.4.

---

## v0.3.3

**Date:** 2026-11-12
**Previous release:** v0.3.2

### Changed

- `mmstracectl` is built on go-mms-trace v0.3.2 (was v0.3.0).

---

## v0.3.2

**Date:** 2026-11-12
**Previous release:** v0.3.1

### Changed

- **Built on go-mms v1.9.1 and go-iec61850 v1.19.1** (were v1.9.0 and v1.19.0), in the library and in `mmstracectl`: range-checked integer conversions and Close-race fixes upstream. The decoding of captures is unchanged.
- CI: shared workflows otfabric/.github v3.6.0 (were v3.3.0 and v3.5.0), otfabric-policy v1.5.0 (was v1.4.2), and golangci-lint v2.15.0 instead of the shared default v2.1.6.

---

## v0.3.1

**Date:** 2026-11-11
**Previous release:** v0.3.0

### Changed

- `mmstracectl` is built on go-mms-trace v0.3.0 (was v0.2.0).

---

## v0.3.0

**Date:** 2026-11-11
**Previous release:** v0.2.1

### Changed

- **Built on go-mms v1.9.0 and go-iec61850 v1.19.0** (were v1.8.0 and v1.17.1), in the library and in `mmstracectl`. The decoding of captures is unchanged. go-mms v1.9.0 enforces the negotiated outstanding-request and nesting limits in its client; go-iec61850 v1.18.0 adds R-GOOSE/R-SV, setting group value banks, BufTm, control checks and an injectable clock, and changes report timing (see their release notes).

---

## v0.2.1

**Date:** 2026-11-11
**Previous release:** v0.2.0

### Changed

- `mmstracectl` is built on go-mms-trace v0.2.0 (was v0.1.3), so the CLI carries the go-mms v1.8.0 decoding of v0.2.0.

---

## v0.2.0

**Date:** 2026-11-11
**Previous release:** v0.1.4

### Changed

- **Built on go-mms v1.8.0 and go-iec61850 v1.17.1** (were v1.7.2 and v1.16.2), in the library and in `mmstracectl`. These are the ISO 9506 and IEC 61850 spec-review releases. What changes in an analysis:
- The confirmed-service CHOICE must be context-specific. A response whose service element is a universal SEQUENCE, such as the Write response `a1 05 02 01 00 30 00` in the public iti captures, is now reported with a decode error; it was decoded before. `testdata/captures/public/expected.json` records one more decode error each for `iti/iec` and `iti/MMS_Specific_Commands/iec61850_write.pcap`.
- Receive accepts BER as X.690 allows (non-minimal lengths and INTEGERs, indefinite length), and ServiceError and Reject PDUs are decoded in full.
- Captures of a go-mms v1.8.0 client end in `release` (Conclude, then A-RELEASE) rather than `conclude`, and a go-mms server answers an unsupported service with a Reject (`reject` status) rather than a ConfirmedError.

---

## v0.1.4

**Date:** 2026-11-10
**Previous release:** v0.1.3

### Changed

- Built on go-iec61850 v1.16.2 (was v1.15.2), for `goose.Decode` and `sv.Decode`. v1.15.2 to v1.16.2 do not change those decoders.
- `mmstracectl` is built on go-mms-trace v0.1.3 (was v0.1.1) and go-iec61850 v1.16.2, so it carries the go-mms v1.7.2 TimeOfDay decoding of v0.1.3.

---

## v0.1.3

**Date:** 2026-11-10
**Previous release:** v0.1.2

### Changed

- **Built on go-mms v1.7.2** (was v1.7.1), in the library and in `mmstracectl`. A TimeOfDay (BinaryTime) whose millisecond field is one day or more now decodes instead of failing the whole PDU: ISO 9506-2:2003 §7.5.1 only requires bits 28–31 to be zero, so a 4-octet value keeps the field as is (up to 2^28−1 ms, a deadline past midnight) and a 6-octet value carries it into the following days. A field with bits 28–31 set is rejected (otfabric/go-mms#30). In a capture, such a PDU is now decoded instead of being reported with a decode error.

---

## v0.1.2

**Date:** 2026-11-10
**Previous release:** v0.1.1

### Fixed

- **`mmstracectl` is built on library v0.1.1.** The v0.1.1 binaries still required library v0.1.0, so a read error after the file header and a gzip capture whose checksum does not match ended the read silently (exit 0). Now the command prints what was read and exits 3. The library is unchanged from v0.1.1.

### Tests

- `TestGzipChecksum` (`cmd/mmstracectl`) runs the command on a gzip capture with a broken checksum, so a pin of an older library fails the tests.

---

## v0.1.1

**Date:** 2026-11-10
**Previous release:** v0.1.0

### Fixed

- **A read error of the input is reported.** A read error after the file header, and a gzip capture whose checksum or length does not match, ended the read like a cut-short file (`File.TruncatedTail`, no error). They now return the result so far with an error wrapping `ErrCorrupt`. The `mmstracectl` binaries of v0.1.1 were built on library v0.1.0 and do not have this fix; v0.1.2 does.
- **An invalid gzip header wraps `ErrFormat`.** It returned the `compress/gzip` error, which wrapped neither sentinel (`mmstracectl` already exited 3).

### Documentation

- Every document checked against the code, the tests and the CLI: corrected claims (the SHA-256 covers the compressed bytes of a gzip capture; an association closes on a FIN in both directions; the CLI examples), the Wireshark comparison and the public captures scoped to what they show, and new [INTEROPERABILITY.md](INTEROPERABILITY.md), [OBSERVABILITY.md](OBSERVABILITY.md) and [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md).

---

## v0.1.0

**Date:** 2026-11-09
**Previous release:** none

### Added

- `trace.Analyze` reads a pcap or pcapng capture (plain or gzip) and returns the MMS associations over ISO-on-TCP (open, close, AARE result, authentication mechanism, TSAPs, negotiated Initiate), their confirmed services paired by invoke ID with a status (`ok`, `error`, `reject`, `unanswered`, `orphan`, `pending`) and the latency, the InformationReports, and the GOOSE and Sampled Values streams with their sequencing issues. MMS is decoded by go-mms v1.7.1, COTP by go-cotp v1.3.0, GOOSE and SV by go-iec61850 v1.15.2.
- `trace.ErrCorrupt` (damage ended the read; the result so far is returned) and `trace.ErrFormat` (not a capture).
- `mmstracectl` with `info`, `associations`, `transactions` (alias `timeline`, filters `--service`, `--status`, `--assoc`), `reports`, `goose`, `sv` and `version`; `--format text|json|csv`, `--port`, `--max-packet`; `MMSTRACECTL_*` environment variables; shell completion; exit codes 0, 2, 3, 10 and 130.
- 12 captures recorded between independent IEC 61850 stacks of otfabric/iec61850-interop (`testdata/captures/interop`, `scripts/record-interop.sh`): MMS, IEC 61850 client, reporter and controller sequences, GOOSE and Sampled Values; every frame decodes and every request is paired.
- 75 public captures (ADSC Zeek MMS traces, ITI ICS-Security-Tools, QUT-ZSS-2023-MMS, ICS-Pcaps with sessions whose MMS names show ABB and Siemens IED models), with manifest, notices and checksums, held to their summaries by `TestPublicCaptures`.
- `make compare-wireshark`: the MMS PDUs of the interop and public captures are compared with Wireshark's dissector by kind, invoke ID and request service (PDUs of associations captured midstream are not compared); all captures match.
- Counters `BareMMS` (MMS straight in COTP, decoded as Wireshark does) and `TSOSegments` (IPv4 total length 0 from segmentation offload, taken at the captured length); `Transaction.ServerRequest` (a request the server sent, as in ObtainFile).
- Fuzz targets `FuzzAnalyze`, `FuzzPcapReader`, `FuzzPcapngReader` and `FuzzLinkIPTCP`.

### Known limitations

- MMS over TLS is not decodable; only TCP port 102 is searched by default.
- Captures of real devices come from public sources only: MMS sessions whose names show ABB and Siemens IED models and a capture named `iedscout.pcap` (ICS-Pcaps), traces from the EPIC testbed (ADSC) and community captures (ITI). Their device firmware and capture dates are not documented. They and the captures between independent stacks (libiec61850, iec61850bean, dscsystems, iec61850-rust, cB-Sigma) match Wireshark's dissector on the compared fields, except that PDUs of associations captured midstream (all of `iedscout.pcap`) are not compared; captures of current devices with documented firmware are still to be added ([LIMITATIONS.md](LIMITATIONS.md), [INTEROPERABILITY.md](INTEROPERABILITY.md)).

---
