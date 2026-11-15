# Errors

The sentinels this module exports. Test them with `errors.Is`. A packet that cannot be used is counted, not an error; only an input that is not a capture, damage that ends the read, or a limit on the input as a whole is an error.

| Error | Package | Meaning |
|---|---|---|
| `ErrFormat` | `trace` | The input is not a pcap or pcapng file, plain or gzip: an unknown magic number, fewer than 4 bytes, a pcap file header cut short, or the gzip magic without a valid gzip header (the error also wraps `gzip.ErrHeader`). An input that could not be read far enough to tell is reported the same way, and the error then also wraps the read error of the caller's `io.Reader`. `Analyze` returns no result. |
| `ErrCorrupt` | `trace` | Damage ended the read. In a pcap file: a record whose captured length exceeds `Options.MaxPacket`, or whose sub-second part is a second or more. In a pcapng file: a block length below its minimum (12 bytes, 28 for a section header), not a multiple of 4 or above 16 MiB, or a section header without its byte-order magic. In any input: a read error of the input after the format is known, and a gzip stream whose checksum or length does not match. The error also wraps what the reader reported: the error of the caller's `io.Reader`, or `gzip.ErrChecksum`. The result holds what was read before it. |
| `ErrLimit` | `trace` | The input goes on past a limit on the input as a whole: more bytes of capture than `Options.MaxBytes` (counted after decompression), or more pcapng sections than `Options.MaxSections`. The capture is not damaged; raising the option reads it whole. The result holds what was read before the limit. |

`Analyze` returns one other error, without a result: `ctx.Err()` when the context is done.

**Retrying.** The same bytes give the same result, so `ErrFormat` and `ErrCorrupt` from the content of a file are final. When the error also wraps an error of the caller's own reader (test it with `errors.Is` or `errors.As`: a timeout, a closed pipe, an I/O error), the read failed, not the capture, and whether to read again is that error's matter. `ErrLimit` goes away with a higher limit.

Some damage is tolerated and is not an error: a last record cut short ends the read with `File.TruncatedTail` set; a damaged pcapng block with a plausible length is skipped and counted in `File.SkippedBlocks`, and so are a packet that names no interface and the interfaces past `Options.MaxInterfaces`; a pcapng packet whose time does not fit in 64 bits of nanoseconds is used without a time and counted in `File.BadTimestamps`. What else is not reported is listed in [LIMITATIONS.md](LIMITATIONS.md#capture-files).

## Counters

What could not be used is counted in `Result.Counters`:

| Counter | Counts |
|---|---|
| `Unsupported["other_tcp"]` | TCP segments to and from ports not in `Options.Ports`. |
| `Unsupported[reason]` | Packets without a usable TCP segment, by reason: `link_unsupported` (a link type `File.Links` names `other`), `not_ip` (other EtherTypes and address families), `not_tcp` (UDP, ICMP, other IP protocols), `tunnel` (IP-in-IP, GRE, VXLAN), `ipsec` (AH, ESP), `short` (headers cut short), `bad_header` (an impossible header length or version), `ipv6_ext_headers` (more than 8 IPv6 extension headers), `fragment_bad` (an IP fragment that cannot belong to a valid datagram: an empty one, one that ends past 65,535 bytes or past the end its datagram's last fragment gave, a second last fragment with another end, and a last fragment that ends before fragments already held, whose datagram is then given up). GOOSE and SV frames on the Ethernet link type are not counted here; on other link types they count as `not_ip`. IP fragments held for reassembly are not counted. |
| `TPKTResync` | Bytes of an MMS connection that are part of no TPKT frame: bytes skipped to find the next frame after a gap, after bytes that are no header (version 3, reserved 0, length at least 7), or at the start of a stream captured from its middle; one byte for each header found there whose COTP TPDU does not decode; and the bytes of an incomplete frame given up to `Options.MaxAssembly`. |
| `COTPErrors` | TPKT frames of a synchronised direction (one in which every frame follows the one before it) whose payload did not decode as a COTP TPDU. Such a frame is passed over as a whole. Where the framing is not synchronised, a header whose TPDU does not decode is counted in `TPKTResync` instead ([ARCHITECTURE.md](ARCHITECTURE.md#4-associations)). |
| `TSDUErrors` | Reassembled TSDUs that did not decode as session, presentation, ACSE or MMS, TSDUs larger than `MaxTSDU`, and TSDUs whose first part was given up to `Options.MaxAssembly`. |
| `BareMMS` | MMS PDUs carried straight in COTP, without session and presentation (not IEC 61850-8-1; some tools send them). They are decoded and paired. |
| `TSOSegments` | Unfragmented IPv4 packets with a total length of 0: captured on the sending host before segmentation offload filled it in. They are used at their captured length. Not an error. |
| `GOOSEErrors` | Frames with EtherType 0x88b8 that go-iec61850's `goose.Decode` rejected. |
| `SVErrors` | Frames with EtherType 0x88ba that go-iec61850's `sv.Decode` rejected. |

An MMS PDU whose service content does not decode is not counted: go-mms sets its `DecodeError` (see `Transaction.Request`, `Transaction.Response` and `Report.PDU`). `File.TruncatedTail`, `File.SkippedBlocks` and `File.BadTimestamps` describe tolerated damage of the file; `Association.Gaps` counts skipped ranges of the TCP byte stream. A response paired with a request across such a loss has the status `uncertain` ([API.md](API.md#transaction)).

`mmstracectl` exit codes: [cmd/mmstracectl/docs/exitcodes.md](cmd/mmstracectl/docs/exitcodes.md).
