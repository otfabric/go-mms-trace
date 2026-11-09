# Architecture

go-mms-trace turns a packet capture into a `trace.Result`: MMS associations with paired transactions and reports, and GOOSE and Sampled Values streams. One pass, offline, in pure Go.

## 1. Pipeline

```text
capture file (pcap / pcapng, plain or gzip)
  │
  ▼ internal/pcapio      records → Packet{Frame, TimeNS, LinkType, Data}
  │
  ├─ EtherType 0x88b8 ──▶ go-iec61850 goose.Decode ──▶ GooseStream (per src MAC, APPID, gocbRef)
  ├─ EtherType 0x88ba ──▶ go-iec61850 sv.Decode    ──▶ SVStream    (per src MAC, APPID, svID)
  │
  ▼ internal/link        Ethernet / SLL / SLL2 / null / raw, VLAN, IPv4/IPv6, IP fragments → TCP segment
  │                      (port filter: Options.Ports, else counted as other_tcp)
  ▼ internal/flow        connection tracking, per-direction reassembly in sequence order, gaps
  │
  ▼ trace (analyze.go)   TPKT framing (RFC 1006) with resync → go-cotp cotp.Decode
  │                      CR: TSAPs, open "connect"; DR/DC: close "disconnect"
  │                      DT: user data appended until EOT → one TSDU
  ▼ go-mms DecodeTSDU    session SPDU → presentation PPDU → ACSE APDU or MMS PDU (mms.Captured)
  │
  ▼ pairing              confirmed-request keyed by invoke ID per association;
                         confirmed-response / confirmed-error / reject close it;
                         unconfirmed → Report; initiate-response → Association.Initiate
```

`trace.Analyze` drives the loop: one packet at a time, checking the context between packets.

## 2. Limits

Every buffer is bounded; what a limit drops is counted.

| Limit | Value | Where | What happens beyond it |
|---|---|---|---|
| Packet record | 256 KiB (`Options.MaxPacket`) | pcapio | the record is damage: `ErrCorrupt` (pcap) or a skipped block (pcapng) |
| pcapng block skipped over | 16 MiB | pcapio | damage: `ErrCorrupt` |
| pcapng options area | 64 KiB | pcapio | options ignored, counted |
| IP fragment reassembly | 1 MiB in total | link | oldest datagram dropped |
| IPv6 extension headers | 8 | link | `ipv6_ext_headers` |
| Tracked TCP connections | 100 000 | flow | least recently seen evicted |
| Out-of-order bytes | 1 MiB per direction, 64 MiB in total | flow | reported as a gap |
| TPKT | 65 535 bytes (its 16-bit length) | trace | — |
| TSDU | 16 MiB (`MaxTSDU`) | trace | TSDU dropped, `TSDUErrors` |

The `Result` itself is held in memory: every association, transaction (with its decoded PDUs), report and stream. A GOOSE stream also keeps the (stNum, sqNum) pairs it has seen and its per-second counts. Memory therefore grows with the number of transactions and GOOSE messages in the capture; see [LIMITATIONS.md](LIMITATIONS.md).

## 3. Packages

| Package | Role |
|---|---|
| `trace` | `Analyze`, the model (`model.go`), the ISO stack and pairing (`analyze.go`), GOOSE and SV (`l2.go`) |
| `internal/pcapio` | pcap and pcapng reader (gzip, streams, SHA-256 of what was read) and writers (used by tests); adapted from go-modbus-trace |
| `internal/link` | link, IP and TCP headers, IP fragment reassembly; adapted from go-modbus-trace |
| `internal/flow` | TCP connection tracking and per-direction reassembly; adapted from go-modbus-trace |
| `cmd/mmstracectl` | the CLI, a nested module with its own `go.mod` so the library does not depend on cobra |

## 4. Associations

An association is created by the first COTP TPDU of a TCP connection whose one end is on an MMS port; that end is the server. The connection's TPDUs then decide:

- `Open`: `midstream` at first; `connect` on a COTP CR; `associate` on an AARQ.
- `Close`: `conclude` on an MMS conclude request or response; `release` on an ACSE RLRQ or RLRE; `abort` on a session abort SPDU or an ACSE ABRT; `disconnect` on a COTP DR or DC, or a TCP FIN, when nothing above set it; `reset` on a TCP RST. A connection the tracker gives up (end of capture, eviction, a new epoch of the same 4-tuple) leaves `Close` empty.
- `Accepted` from the AARE result (0 is accepted); `Authentication` from the AARQ's mechanism name. The authentication value is never decoded.

A TCP gap resets the TPKT framing and the TSDU being assembled in that direction and increments `Gaps`. Garbage before a TPKT header is skipped byte by byte (`TPKTResync`).

## 5. Pairing

Per association, a confirmed request is held by invoke ID until a confirmed response, confirmed error or reject with that invoke ID arrives (`ok`, `error`, `reject`). A response without a held request becomes an `orphan` transaction. When the connection closes, the requests still held become `unanswered` (and count in `Association.Unanswered`); at the end of the capture, the requests of associations not seen closing become `pending`. A reject without an invoke ID is not paired.

## 6. GOOSE and Sampled Values

Ethernet frames (after any 802.1Q, 802.1ad or 0x9100 tags) with EtherType 0x88b8 are decoded with go-iec61850's `goose.Decode`, those with 0x88ba with `sv.Decode`. Other link types are not searched for them. Each GOOSE message is compared with the previous one of its stream (section "GooseStream" of [API.md](API.md) lists the issues); each SV ASDU's smpCnt with the previous one of its stream.

## 7. Dependencies

| Module | Used for |
|---|---|
| github.com/otfabric/go-mms v1.7.1 | `mms.DecodeTSDU` and the `mms.Captured*` types; tests also run real go-mms clients and servers (`transport/iso`) to record associations |
| github.com/otfabric/go-cotp v1.3.0 | `cotp.Decode` |
| github.com/otfabric/go-iec61850 v1.15.2 | `goose.Decode`, `sv.Decode` |

The library opens no socket and runs no program; `depguard` and `forbidigo` in `.golangci.yml` enforce it for non-test code. go-iec61850's `goose` and `sv` packages also implement live capture and so link `golang.org/x/sys/unix`; the library calls only their decoders ([LIMITATIONS.md](LIMITATIONS.md)).
