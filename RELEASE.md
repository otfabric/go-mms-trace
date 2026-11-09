# go-mms-trace Releases

## v0.1.0

**Date:** 2026-11-09
**Previous release:** none

### Added

- `trace.Analyze` reads a pcap or pcapng capture (plain or gzip) and returns the MMS associations over ISO-on-TCP (open, close, AARE result, authentication mechanism, TSAPs, negotiated Initiate), their confirmed services paired by invoke ID with a status (`ok`, `error`, `reject`, `unanswered`, `orphan`, `pending`) and the latency, the InformationReports, and the GOOSE and Sampled Values streams with their sequencing issues. MMS is decoded by go-mms v1.7.1, COTP by go-cotp v1.3.0, GOOSE and SV by go-iec61850 v1.15.0.
- `trace.ErrCorrupt` (damage ended the read; the result so far is returned) and `trace.ErrFormat` (not a capture).
- `mmstracectl` with `info`, `associations`, `transactions` (alias `timeline`, filters `--service`, `--status`, `--assoc`), `reports`, `goose`, `sv` and `version`; `--format text|json|csv`, `--port`, `--max-packet`; `MMSTRACECTL_*` environment variables; shell completion; exit codes 0, 2, 3, 10 and 130.
- 12 captures recorded between independent IEC 61850 stacks of otfabric/iec61850-interop (`testdata/captures/interop`, `scripts/record-interop.sh`): MMS, IEC 61850 client, reporter and controller sequences, GOOSE and Sampled Values; every frame decodes and every request is paired.
- 75 public captures (ADSC Zeek MMS traces, ITI ICS-Security-Tools, QUT-ZSS-2023-MMS, ICS-Pcaps with ABB and Siemens IED sessions), with manifest, notices and checksums, held to their summaries by `TestPublicCaptures`.
- `make compare-wireshark`: every MMS PDU of the interop and public captures is compared with Wireshark's dissector; all match.
- Counters `BareMMS` (MMS straight in COTP, decoded as Wireshark does) and `TSOSegments` (IPv4 total length 0 from segmentation offload, taken at the captured length); `Transaction.ServerRequest` (a request the server sent, as in ObtainFile).
- Fuzz targets `FuzzAnalyze`, `FuzzPcapReader`, `FuzzPcapngReader` and `FuzzLinkIPTCP`.

### Known limitations

- MMS over TLS is not decodable; only TCP port 102 is searched by default.
- No captures of real devices yet; the captures between independent stacks (libiec61850, iec61850bean, dscsystems, iec61850-rust, cB-Sigma) decode completely ([LIMITATIONS.md](LIMITATIONS.md), [TESTING.md](TESTING.md)).

---
