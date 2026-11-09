# Errors

The sentinels this module exports. Test them with `errors.Is`. A packet that cannot be used is counted, not an error; only an input that is not a capture, or damage that ends the read, is an error. Neither sentinel is retryable: the same input gives the same result.

| Error | Package | Meaning |
|---|---|---|
| `ErrFormat` | `trace` | The input is not a pcap or pcapng file, plain or gzip: an unknown magic number, fewer than 4 bytes, a pcap file header cut short, or the gzip magic without a valid gzip header (the error also wraps `gzip.ErrHeader`). `Analyze` returns no result. |
| `ErrCorrupt` | `trace` | Damage ended the read. In a pcap file: a record whose captured length exceeds `Options.MaxPacket`, or whose sub-second part is a second or more. In a pcapng file: a block length below its minimum (12 bytes, 28 for a section header), not a multiple of 4 or above 16 MiB, or a section header without its byte-order magic. In any input: a read error of the input after the file header, and a gzip stream whose checksum or length does not match (the error also wraps the reader's error, such as `gzip.ErrChecksum`). The result holds what was read before it. |

`Analyze` returns one other error, without a result: `ctx.Err()` when the context is cancelled.

Some damage is tolerated and is not an error: a last record cut short ends the read with `File.TruncatedTail` set; a damaged pcapng block with a plausible length is skipped and counted in `File.SkippedBlocks`. What else is not reported is listed in [LIMITATIONS.md](LIMITATIONS.md#capture-files).

## Counters

What could not be used is counted in `Result.Counters`:

| Counter | Counts |
|---|---|
| `Unsupported["other_tcp"]` | TCP segments to and from ports not in `Options.Ports`. |
| `Unsupported[reason]` | Packets without a usable TCP segment, by reason: `link_unsupported` (a link type `File.Links` names `other`), `not_ip` (other EtherTypes and address families), `not_tcp` (UDP, ICMP, other IP protocols), `tunnel` (IP-in-IP, GRE, VXLAN), `ipsec` (AH, ESP), `short` (headers cut short), `bad_header` (an impossible header length or version), `ipv6_ext_headers` (more than 8 IPv6 extension headers), `fragment_bad` (an IP fragment that cannot belong to a valid datagram). GOOSE and SV frames on the Ethernet link type are not counted here; on other link types they count as `not_ip`. IP fragments held for reassembly are not counted. |
| `TPKTResync` | Bytes skipped to find the next TPKT header (version 3, reserved 0, length at least 7) after a gap or garbage. |
| `COTPErrors` | TPKT payloads that did not decode as a COTP TPDU. |
| `TSDUErrors` | Reassembled TSDUs that did not decode as session, presentation, ACSE or MMS, and TSDUs larger than `MaxTSDU`. |
| `BareMMS` | MMS PDUs carried straight in COTP, without session and presentation (not IEC 61850-8-1; some tools send them). They are decoded and paired. |
| `TSOSegments` | Unfragmented IPv4 packets with a total length of 0: captured on the sending host before segmentation offload filled it in. They are used at their captured length. Not an error. |
| `GOOSEErrors` | Frames with EtherType 0x88b8 that go-iec61850's `goose.Decode` rejected. |
| `SVErrors` | Frames with EtherType 0x88ba that go-iec61850's `sv.Decode` rejected. |

An MMS PDU whose service content does not decode is not counted: go-mms sets its `DecodeError` (see `Transaction.Request`, `Transaction.Response` and `Report.PDU`). `File.TruncatedTail` and `File.SkippedBlocks` describe tolerated damage of the file; `Association.Gaps` counts skipped ranges of the TCP byte stream.

`mmstracectl` exit codes: [cmd/mmstracectl/docs/exitcodes.md](cmd/mmstracectl/docs/exitcodes.md).
