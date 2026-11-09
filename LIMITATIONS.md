# Limitations

What go-mms-trace does not do, or has not proven yet. The evidence for what it does is in [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md).

## Scope

- **Offline only.** The library reads a capture; it does not capture live, and the result reflects only what the capture point saw.
- **No streaming API.** `Analyze` returns once the whole input is read; nothing is available before. `mmstracectl` reads every capture named on the command line before it writes anything, so a capture piped from a running `tcpdump` produces output only when the pipe ends, and an interrupt (exit 130) discards what was read.
- **Times are capture timestamps.** Latencies and per-second rates come from the capture's clock and resolution at the capture point, not from the devices; they are not a timing measurement of the IEDs.

## MMS

- **MMS over TLS is not decodable.** IEC 62351-4 secures MMS with TLS (usually on TCP port 3782); the capture holds ciphertext. Adding 3782 to `Options.Ports` creates associations for those connections only where a TPKT-like header happens to decode; their content is counted (`TPKTResync`, `COTPErrors`), not decoded.
- **Only TCP port 102 by default.** MMS on another port is found only when that port is given in `Options.Ports` (`mmstracectl --port`). There is no detection by content.
- **What go-mms decodes is what is shown.** Services that go-mms's `DecodeTSDU` does not model keep their raw content in `mms.CapturedPDU.Raw`; a modelled service that fails to decode has `DecodeError` set and is not counted in `Counters`. The library adds no decoding of its own above COTP. go-mms names every unconfirmed PDU `InformationReport`, so an UnsolicitedStatus or EventNotification appears as a `Report` with `DecodeError` set.
- **Not paired, not counted:** responses and rejects without an invoke ID, cancel request, response and error PDUs, initiate errors and conclude errors (a conclude error does not set `Close`). The MMS initiate request is not kept; only the initiate response (`Association.Initiate`).
- **Authentication values are never decoded**, only the mechanism (`none`, `password`, `other`).
- **One association per TCP connection.** A new AARQ on the same connection after a release is counted in the same association. A session-level refuse SPDU does not set `Accepted`.
- **Associations captured midstream** have no AARQ, AARE or TSAPs; a PDU in a skipped range of the TCP stream is lost, and the framing restarts at the next TPKT header.

## GOOSE and Sampled Values

- **Only on the Ethernet link type.** Frames in Linux cooked captures (SLL, SLL2) are not searched for the GOOSE and SV EtherTypes (they count as `not_ip`); routable GOOSE and SV (IEC 61850-90-5, over UDP) are not decoded.
- **Sequencing only.** Streams report counts, flags and sequencing issues; the data set values are decoded by go-iec61850 but not kept in the `Result`.
- **Sampled Values sequencing is per stream and in capture order**; any fall of smpCnt is taken as a counter wrap, so samples lost across a wrap, and reordered ASDUs, are not counted.

## Capture files

- **Link types:** Ethernet (with 802.1Q, 802.1ad and 0x9100 tags), Linux cooked v1 and v2, BSD null and OpenBSD loop, raw IP, raw IPv4 and raw IPv6. Every other link type is counted as `link_unsupported`.
- **Tunnels and IPsec are not opened:** IP-in-IP, GRE, VXLAN, AH and ESP are counted (`tunnel`, `ipsec`). Checksums are never verified.
- **IP fragments** are reassembled within 1 MiB in total; datagrams dropped by that budget, and fragments of datagrams never completed, are not reported in the `Result`. A fragment cut by the snap length is counted as `short`.
- **TCP:** retransmissions, out-of-order segments and conflicting overlaps (where the first data wins) are handled internally but not reported in the `Result`. A TCP FIN in only one direction does not close the association. Packets of a closed connection, other than a new SYN, are ignored.
- **Not reported:** pcapng blocks of unknown type, interface statistics, malformed or oversized (above 64 KiB) option areas, and pcapng simple packet blocks' lack of a timestamp (their time is 0).

## Memory

`Analyze` returns the whole result: every transaction with its decoded PDUs, every report, and per GOOSE stream the set of (stNum, sqNum) pairs seen and a count per second. The buffers of the pipeline are bounded ([ARCHITECTURE.md](ARCHITECTURE.md#2-limits)), but the result is not: it grows with the capture.

## Evidence

- **Real devices only through public captures.** Besides the generated fixtures and the captures between independent stacks (`testdata/captures/interop`), the real-device evidence is the public captures in `testdata/captures/public`: ICS-Pcaps captures whose MMS names show ABB and Siemens IED models, traces from the EPIC testbed (ADSC) and community captures (ITI). Their device models, firmware and capture dates are not documented by their sources. One of the four sources (ICS-Pcaps) states no licence ([testdata/captures/public/NOTICE.md](testdata/captures/public/NOTICE.md)).
- **The Wireshark comparison is partial and manual.** `make compare-wireshark` compares the MMS PDUs per capture by kind, invoke ID and request service, not values, object names or error codes, and not GOOSE or SV; PDUs of associations captured midstream are not compared, so the capture named `iedscout.pcap` (all midstream) is not compared at all. It is not run in CI. Details: [INTEROPERABILITY.md](INTEROPERABILITY.md#comparison-with-wireshark).
- **No live interop run.** The captures between independent stacks were recorded once (2026-11-09) and are replayed in tests; no independent stack runs in this repository's CI.

## Dependencies

- go-iec61850's `goose` and `sv` packages implement live capture as well as decoding, so this module links `golang.org/x/sys/unix` through them on Unix platforms, although it only calls `goose.Decode` and `sv.Decode`. A decode-only split of those packages is a go-iec61850 follow-up.
