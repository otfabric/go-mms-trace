# go-mms-trace Releases

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
