# Errors

The sentinels this module exports. Test them with `errors.Is`. A packet that cannot be used is counted, not an error, unless the file itself is unreadable.

| Error | Package | Meaning |
|---|---|---|
| `ErrFormat` | `trace` | The input is not a pcap or pcapng file (plain or gzip). `Analyze` returns no result. |
| `ErrCorrupt` | `trace` | Damage ended the read: a record or block with an impossible length. The result holds what was read before it. |

`Analyze` also returns `ctx.Err()` when the context is cancelled, and the error of the reader for an input that cannot be read (wrapped in `ErrCorrupt` once the header was read).

## Counters

What could not be used is counted in `Result.Counters`:

| Counter | Counts |
|---|---|
| `Unsupported["other_tcp"]` | TCP segments to and from ports not in `Options.Ports`. |
| `Unsupported[reason]` | Packets without a usable TCP segment, by reason: `link_unsupported`, `not_ip`, `not_tcp`, `tunnel`, `ipsec`, `short`, `bad_header`, `ipv6_ext_headers`, `fragment_bad`. GOOSE and SV frames are not counted here. |
| `TPKTResync` | Bytes skipped to find the next TPKT header (version 3, reserved 0, length at least 7) after a gap or garbage. |
| `COTPErrors` | TPKT payloads that did not decode as a COTP TPDU. |
| `TSDUErrors` | Reassembled TSDUs that did not decode as session, presentation, ACSE or MMS, and TSDUs larger than `MaxTSDU`. |
| `BareMMS` | MMS PDUs carried straight in COTP, without session and presentation (not IEC 61850-8-1; some tools send them). They are decoded and paired; Wireshark decodes them too. |
| `TSOSegments` | IPv4 packets with a total length of 0: captured on the sending host before segmentation offload filled it in. They are used at their captured length, as Wireshark does. Not an error. |
| `GOOSEErrors` | Frames with EtherType 0x88b8 that did not decode as GOOSE. |
| `SVErrors` | Frames with EtherType 0x88ba that did not decode as Sampled Values. |

`File.TruncatedTail` (the last record was cut short) and `File.SkippedBlocks` (damaged pcapng blocks with a plausible length) describe tolerated damage; `Association.Gaps` counts holes in the TCP byte stream.

`mmstracectl` exit codes: [cmd/mmstracectl/docs/exitcodes.md](cmd/mmstracectl/docs/exitcodes.md).
