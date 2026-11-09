# Interoperability

go-mms-trace sends nothing, so it does not interoperate with a peer at run time. Its interoperability evidence is how it decodes traffic that other implementations produced:

1. captures recorded between independent IEC 61850 stacks of otfabric/iec61850-interop, checked in CI by `TestInteropCaptures`;
2. public captures from four outside sources, checked in CI by `TestPublicCaptures` against a recorded summary;
3. a comparison of the MMS PDUs of both sets with Wireshark's dissector, run by hand (`make compare-wireshark`).

What each of these does not show is at the end of each section and in [LIMITATIONS.md](LIMITATIONS.md#evidence).

## Captures between independent stacks

`testdata/captures/interop` holds 12 captures recorded on 2026-11-09 with `scripts/record-interop.sh` from the digest-pinned images of otfabric/iec61850-interop v1.4.0 (contract 1.3). No OT Fabric code runs on either end. MMS runs on TCP 1102, the port of the images.

| Stack | Version in iec61850-interop v1.4.0 (`versions.yaml`) | Licence | Roles in these captures |
|---|---|---|---|
| libiec61850 (MZ Automation) | commit 6e265c54af66 | GPL-3.0-only (or commercial) | MMS server and client, IED server, client, reporter and controller, GOOSE and SV publisher |
| iec61850bean (beanit) | 1.9.0 | Apache-2.0 | IED server and client |
| dscsystems go-iec61850 | v0.6.6 | GPL-3.0 | MMS server, IED server and client |
| iec61850-rust | commit d4e895217f36 | MIT OR Apache-2.0 | MMS client, IED reporter |
| cB-Sigma iec61850 and iec61850-sim | v0.1.0 | Apache-2.0 | IED client, GOOSE publisher |

| Capture (`<name>.pcap`) | Server or publisher | Client | Content |
|---|---|---|---|
| `libiec61850_mms-server_mms-client-iec61850-rust` | libiec61850 | iec61850-rust | MMS service sequence: identify, name lists, status, reads and writes of every type, named variable lists, files (including ObtainFile), journals, InformationReports, deliberate negative cases, then conclude, abort and server abort on further associations |
| `dscsystems_mms-server_mms-client-libiec61850` | dscsystems | libiec61850 | the same sequence |
| `libiec61850_ied-server_ied-client-iec61850bean` | libiec61850 | iec61850bean | IEC 61850 client sequence: server, logical device and logical node directories, reads, a write, a data set read, conclude |
| `iec61850bean_ied-server_ied-client-libiec61850` | iec61850bean | libiec61850 | the same client sequence |
| `libiec61850_ied-server_ied-client-dscsystems` | libiec61850 | dscsystems | the same client sequence |
| `libiec61850_ied-server_ied-client-cbsigma` | libiec61850 | cB-Sigma | the same client sequence |
| `iec61850bean_ied-server_ied-reporter-libiec61850` | iec61850bean | libiec61850 | enable a report control block, general interrogation, one report, disable |
| `libiec61850_ied-server_ied-reporter-iec61850-rust` | libiec61850 | iec61850-rust | enable a report control block, general interrogation, one report, disable |
| `dscsystems_ied-server_ied-controller-libiec61850` | dscsystems | libiec61850 | control of SPCSO2: read ctlModel, select, operate, read stVal |
| `libiec61850_goose-publisher` | libiec61850 | | GOOSE, one state change |
| `cbsigma_goose-publisher` | cB-Sigma | | GOOSE, one state change |
| `libiec61850_sv-publisher` | libiec61850 | | Sampled Values 9-2LE, 4,000 samples/s for 3.6 s |

`manifest.json` records each file's peers, image digests, the stacks' licences and the checksum (also in `SHA256SUMS`); the `.client.jsonl` files are the clients' own logs of their operations. The captures are recordings of protocol traffic, not code of the stacks.

**What `TestInteropCaptures` checks** (`trace/interop_test.go`): the checksum of each file; no TPKT, COTP, TSDU, GOOSE or SV errors; for MMS captures, that every association was opened with an AARQ, accepted, has an initiate response, no gaps and was seen ending, that every transaction is `ok` or `error` (the error ones are the sequence's deliberate negative cases) with no `DecodeError` in request or response, and that each reporter capture has one report; for GOOSE, one stream with one state change and no issues; for SV, one stream with at least 1,000 ASDUs and none lost or repeated.

**What it does not check:** the decoded values against the clients' logs (the `.client.jsonl` files are not read by the test), and any stack version other than the pinned images.

### Reproduce

```sh
# Pull the images of iec61850-interop v1.4.0 first; the script looks them up locally.
IEC61850_INTEROP=../iec61850-interop make record-interop OUT=/tmp/interop-captures
```

`scripts/record-interop.sh` needs Docker and a checkout of iec61850-interop (for the GOOSE and SV fixtures); it writes the captures, the clients' logs and `recorded.jsonl` (file, peers, image digests) to `OUT`. Without `OUT`, `make record-interop` writes into `testdata/captures/interop`.

## Public captures

`testdata/captures/public` holds 75 public captures from four sources, each pinned by source commit, path, URL and checksum in `manifest.json` (also `SHA256SUMS`), with the licences in [NOTICE.md](testdata/captures/public/NOTICE.md):

| Directory | Source | Licence (manifest.json) | Origin as the source describes it |
|---|---|---|---|
| `adsc-zeek/` | smartgridadsc/MMS-protocol-parser-for-Zeek-IDS | BSD-3-Clause | one capture per MMS service and optional field; generated with libIEC61850 v1.4.0, some samples from the EPIC testbed of SUTD |
| `iti/` | ITI/ICS-Security-Tools | CC-BY-4.0 | community uploads to pcapr.net; several are hand-crafted (MMS straight in COTP, responses without a service) |
| `qut-zss-2023-mms/` | CSCRC-SCREED/QUT-ZSS-2023-MMS | GPL-3.0 (NOTICE.md: stated in the dataset metadata) | a simulated zone substation, MMS between an HMI and several IEDs |
| `ics-pcaps/` | EmreEkin/ICS-Pcaps | none stated (used at the maintainer's direction) | collected from various places, origin per file not stated; the `Substation` set shows ABB and Siemens IED models in its MMS names |

Six files of these sources are left out and listed under `excluded` in `manifest.json`: four byte-identical duplicates, Wireshark's `mms.pcap.gz` (its content is identical to an ITI capture) and one JSON text named `.pcap`.

**What `TestPublicCaptures` checks** (`trace/public_test.go`): the checksum of each file, and that `Analyze` reads it without error and finds what `expected.json` records: packets, associations by open and close, transactions by status and service, reports, the number of PDUs with a `DecodeError`, GOOSE and SV stream summaries and the counters (`go test ./trace -run TestPublicCaptures -update` rewrites it).

**What it does not check:** that the summary is right. `expected.json` records what the library found when it was written, including decode errors and counters on some captures (for example the hand-crafted ITI captures); a change shows up as a test failure to review, not as a correctness verdict.

## Comparison with Wireshark

`make compare-wireshark` (needs `tshark` and Python 3) builds `bin/mmstracectl` and runs `scripts/compare-wireshark.py` over the interop captures (with `--port 1102`) and the public captures (port 102). For each capture it collects the MMS PDUs that mmstracectl reports and those that `tshark` dissects (with TCP on the port decoded as TPKT), and compares the two multisets of:

- confirmed requests, as (invoke ID, service);
- confirmed responses, confirmed errors and rejects, as (kind, invoke ID);
- unconfirmed PDUs, by count.

A capture passes when both multisets are equal. **Not compared:** frame numbers, values, object names, error classes and codes, the service of responses, latencies, initiate and conclude PDUs, ACSE and session PDUs, association open and close, GOOSE and Sampled Values; and PDUs of associations captured midstream, which are counted but not compared, since Wireshark needs the association to dissect MMS.

Result on 2026-11-10 with Wireshark 4.6.9 and go-mms v1.7.1: all 87 captures pass. 11,722 PDUs in 61 captures were compared; 561 PDUs in associations captured midstream were not, and 14 captures (among them `ics-pcaps/iedscout.pcap`, `ics-pcaps/pres.pcap` and `ics-pcaps/pres1.pcap`) have MMS only in such associations; the other 12 captures without compared PDUs hold no PDU of a compared kind: nine GOOSE and SV captures, two with only initiate, conclude or cancel PDUs (`adsc-zeek/conclude.pcap`, `iti/MMS_Specific_Commands/mms-cancelRequest.pcap`), and `iti/m-send-req.mms.pcap`, which has no traffic on TCP port 102. The comparison is not run in CI.

The comparison found, and these are fixed: IPv4 packets with a total length of 0 (segmentation offload, in the ABB and Siemens captures) were dropped; invoke IDs were paired across both directions (a server's requests during ObtainFile); MMS straight in COTP was not decoded; and in go-mms v1.7.0 unimplemented services were named `Unknown`, a response without a service was an error, and a GetVariableAccessAttributes response with a primitive address did not decode.
