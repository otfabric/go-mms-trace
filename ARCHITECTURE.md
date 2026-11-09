# Architecture

go-mms-trace turns a packet capture into a `trace.Result`: MMS associations with paired transactions and reports, and GOOSE and Sampled Values streams. One pass over the input, offline, in pure Go, in the caller's goroutine: the library starts no goroutines and keeps no state between calls.

## 1. Pipeline

```text
capture file (pcap / pcapng, plain or gzip)
  │
  ▼ internal/pcapio      records → Packet{Frame, TimeNS, LinkType, Data}
  │
  │  (Ethernet link type only)
  ├─ EtherType 0x88b8 ──▶ go-iec61850 goose.Decode ──▶ GooseStream (per src MAC, APPID, gocbRef)
  ├─ EtherType 0x88ba ──▶ go-iec61850 sv.Decode    ──▶ SVStream    (per src MAC, APPID, svID)
  │
  ▼ internal/link        Ethernet / SLL / SLL2 / null / loop / raw / IPv4 / IPv6 link types, VLAN tags,
  │                      IPv4/IPv6, IP fragment reassembly → TCP segment
  │                      (port filter: Options.Ports, else counted as other_tcp)
  ▼ internal/flow        connection tracking, per-direction reassembly in sequence order, gaps
  │                      (retransmitted bytes delivered once; on an overlap the first data wins)
  │
  ▼ trace (analyze.go)   TPKT framing (RFC 1006) with resync → go-cotp cotp.Decode
  │                      CR: TSAPs, open "connect"; DR/DC: close "disconnect"
  │                      DT: user data appended until EOT → one TSDU
  ▼ go-mms DecodeTSDU    session SPDU → presentation PPDU → ACSE APDU or MMS PDU (mms.Captured)
  │
  ▼ pairing              confirmed-request keyed by invoke ID per association and direction;
                         confirmed-response / confirmed-error / reject close it;
                         unconfirmed → Report; initiate-response → Association.Initiate
```

`trace.Analyze` drives the loop: one packet at a time, checking the context before each packet. Checksums (IP, TCP) are never verified. The library writes no logs and has no hooks or callbacks: everything it observes is in the `Result` ([ERRORS.md](ERRORS.md#counters) for the counters).

## 2. Limits

Every buffer of the pipeline is bounded. What a limit drops is counted or reported as a gap, except where the table says it is not reported.

| Limit | Value | Where | What happens beyond it |
|---|---|---|---|
| Packet record | 256 KiB (`Options.MaxPacket`) | pcapio | the record is damage: `ErrCorrupt` (pcap) or a skipped block (pcapng, `File.SkippedBlocks`) |
| pcapng block | 16 MiB | pcapio | damage: `ErrCorrupt` |
| pcapng options area | 64 KiB | pcapio | options ignored; not reported in the `Result` |
| IP fragment reassembly | 1 MiB in total, with a per-fragment overhead charged | link | oldest incomplete datagram dropped; not reported in the `Result` |
| IPv6 extension headers | 8 | link | `ipv6_ext_headers` |
| Tracked TCP connections | 100 000 | flow | least recently seen evicted (its association stays open, its requests `pending`) |
| Out-of-order bytes | 1 MiB per direction, 64 MiB in total (128 bytes charged per held segment besides its bytes) | flow | skipped as a gap (`Association.Gaps`) |
| TPKT | 65 535 bytes (its 16-bit length) | trace | cannot be exceeded |
| TSDU | 16 MiB (`MaxTSDU`) | trace | TSDU dropped, `TSDUErrors` |

The `Result` itself is held in memory and is not bounded: every association, transaction (with its decoded PDUs), report and stream. A GOOSE stream also keeps every (stNum, sqNum) pair it has seen and a count per second of capture time. Memory therefore grows with the number of transactions, reports and GOOSE messages in the capture; see [LIMITATIONS.md](LIMITATIONS.md#memory).

## 3. Packages

| Package | Role |
|---|---|
| `trace` | `Analyze`, the model (`model.go`), the ISO stack and pairing (`analyze.go`), GOOSE and SV (`l2.go`) |
| `internal/pcapio` | pcap and pcapng reader (gzip, streams, SHA-256 of what was read), writers (used by tests) and a random-access index (not used by `trace`); adapted from go-modbus-trace |
| `internal/link` | link, IP and TCP headers, IP fragment reassembly; adapted from go-modbus-trace |
| `internal/flow` | TCP connection tracking and per-direction reassembly; adapted from go-modbus-trace |
| `cmd/mmstracectl` | the CLI, a nested module with its own `go.mod` so the library does not depend on cobra |

Imports within the module (`go list -f '{{.Imports}}' ./...`): `trace` imports `internal/pcapio`, `internal/link` and `internal/flow`; `internal/flow` imports `internal/link` and `internal/pcapio`; `internal/link` and `internal/pcapio` import only the standard library.

## 4. Associations

An association is created by the first COTP TPDU that decodes on a TCP connection with one end on an MMS port; that end is the server (when both ends are, the sender of the first captured packet is the server). A TCP connection here is one epoch of a 4-tuple: a SYN after the connection closed, or a SYN far (more than 1 MiB) from the expected sequence number, starts a new epoch and so a new association. The connection's TPDUs then decide:

- `Open`: `midstream` at first; `connect` on a COTP CR; `associate` on an AARQ.
- `Close`: `conclude` on an MMS conclude request or response; `release` on an ACSE RLRQ or RLRE (replacing an earlier `conclude`); `abort` on a session abort SPDU or an ACSE ABRT (replacing anything earlier); `disconnect` on a COTP DR or DC, or a TCP FIN in both directions, and `reset` on a TCP RST, each only when nothing set `Close` before. A connection the tracker gives up (end of capture, eviction, a new epoch of the same 4-tuple) leaves `Close` empty. Packets of a closed connection other than a new SYN are ignored.
- `Accepted` from the AARE result (0 is accepted); `Authentication` from the AARQ's mechanism name. The authentication value is never decoded.

A skipped range of the TCP stream (a gap: bytes not captured, cut by the snap length or dropped by a reassembly limit) resets the TPKT framing and the TSDU being assembled in that direction and increments `Gaps`. Garbage before a TPKT header is skipped byte by byte (`TPKTResync`). COTP DT user data is appended until a DT with EOT; other TPDU types besides CR, DR and DC carry nothing the library uses.

## 5. Pairing

Per association and direction, a confirmed request is held by invoke ID until a confirmed response, confirmed error or reject with that invoke ID arrives in the other direction (`ok`, `error`, `reject`). A new request with the invoke ID of a held one makes the held one `unanswered`. A response without a held request becomes an `orphan` transaction. When the connection closes, the requests still held become `unanswered` (and count in `Association.Unanswered`); when the association was not seen closing (end of capture, eviction, a new epoch), they become `pending`. Responses and rejects without an invoke ID, cancel PDUs and initiate and conclude errors are not paired and not counted.

## 6. GOOSE and Sampled Values

Frames of the Ethernet link type (after any 802.1Q, 802.1ad or 0x9100 tags) with EtherType 0x88b8 are decoded with go-iec61850's `goose.Decode`, those with 0x88ba with `sv.Decode`. Other link types are not searched for them. Each GOOSE message is compared with the previous one of its stream ([API.md](API.md#goosestream) lists the issues); each SV ASDU's smpCnt with the previous one of its stream ([API.md](API.md#svstream)).

## 7. Dependencies

| Module | Used for |
|---|---|
| github.com/otfabric/go-mms v1.7.1 | `mms.DecodeTSDU` and the `mms.Captured*` types; tests also run real go-mms clients and servers (`transport/iso`) to record associations |
| github.com/otfabric/go-cotp v1.3.0 | `cotp.Decode` (it requires go-tpkt v1.1.0) |
| github.com/otfabric/go-iec61850 v1.15.2 | `goose.Decode`, `sv.Decode` |

The library opens no socket and runs no program; `depguard` and `forbidigo` in `.golangci.yml` enforce it for non-test code. go-iec61850's `goose` and `sv` packages also implement live capture and so link `golang.org/x/sys/unix`; the library calls only their decoders ([LIMITATIONS.md](LIMITATIONS.md)).
