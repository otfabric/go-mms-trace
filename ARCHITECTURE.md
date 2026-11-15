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

The input as a whole and every buffer of the pipeline are bounded, in bytes and in the work a packet costs. What a limit drops is counted or reported as a gap, except where the table says it is not reported. Each limit has a test that measures memory or work against it ([TESTING.md](TESTING.md#5-limits-and-budgets)).

| Limit | Value | Where | What happens beyond it |
|---|---|---|---|
| Capture read | 16 GiB, counted after decompression (`Options.MaxBytes`, `DefaultMaxBytes`). An hour of one Sampled Values stream at 4800 frames a second is about 2.5 GiB, and capture tools rotate their files well below 16 GiB | pcapio | the read ends there: `ErrLimit`, with the result so far |
| Packet record | 256 KiB (`Options.MaxPacket`) | pcapio | the record is damage: `ErrCorrupt` (pcap) or a skipped block (pcapng, `File.SkippedBlocks`) |
| pcapng block | 16 MiB | pcapio | damage: `ErrCorrupt` |
| pcapng interfaces | 65,536 over all sections (`Options.MaxInterfaces`, `DefaultMaxInterfaces`). A capture has a handful per section; a file merged from thousands of captures stays below it | pcapio | a further interface is skipped with the packets captured on it (`File.SkippedBlocks`) |
| pcapng sections | 65,536 (`Options.MaxSections`, `DefaultMaxSections`). A capture has one; captures joined end to end have one each (hourly files of seven years are 61,000) | pcapio | the read ends there: `ErrLimit`, with the result so far |
| pcapng options area | 64 KiB per block; 16 MiB of option text (names, descriptions, comments) kept per input, 250 bytes for each interface and section at their limits | pcapio | options ignored, text not kept; not reported in the `Result` |
| IP fragment reassembly | 1 MiB in total, with a per-fragment overhead charged | link | oldest incomplete datagram dropped; not reported in the `Result` |
| IPv6 extension headers | 8 | link | `ipv6_ext_headers` |
| Tracked TCP connections | 100 000 | flow | least recently seen evicted (its association stays open, its requests `pending`) |
| Out-of-order bytes | 1 MiB per direction, 64 MiB in total (128 bytes charged per held segment besides its bytes) | flow | skipped as a gap (`Association.Gaps`): beyond the total, the connection that holds the most gives up its first hole |
| TPKT | 65 535 bytes (its 16-bit length) | trace | cannot be exceeded |
| TSDU | 16 MiB (`MaxTSDU`) | trace | TSDU dropped, `TSDUErrors` |
| Incomplete TPKT frames and TSDUs | 64 MiB over all connections (`Options.MaxAssembly`, `DefaultMaxAssembly`): the size of the out-of-order budget. A PDU is in assembly only between its first and its last TCP segment | trace | the direction that has waited longest gives up what it holds: `TSDUErrors` for its TSDU, `TPKTResync` for the bytes of its frame |

**Bytes.** A record or block is read in steps, so an input that declares a length and does not hold it costs no more than it holds. With the limits above the pipeline holds at most: the reader's buffers (two of 256 KiB and one that grows to the largest record or block read), 16 MiB of option text and 65,536 interfaces, 1 MiB of fragments, 64 MiB of out-of-order segments, 64 MiB of frames and TSDUs in assembly, and about 1.1 KiB for each tracked connection (109 MiB for the 100,000 tracked at the end of a pass over 250,000 connections of one segment each: `TestConnectionLimitHeap`, darwin/arm64, Go 1.27.4, 2026-11-14).

**Work.** A packet costs an amount of work that does not grow with the number of connections tracked: a connection is found by a map, the least recently seen one is the end of a list, the connection that gives up a hole at the total out-of-order budget is the first of a heap of the connections that hold bytes, and the direction that gives up its assembly is the end of a list. Within one direction a held segment is put in sequence order among at most 8,192 others (1 MiB at 128 bytes each), and a fragment among those of its datagram.

**The result.** The `Result` itself is held in memory and is not bounded other than by `Options.MaxBytes`: every association, transaction (with its decoded PDUs), report and stream. Its size grows with the number of transactions and reports in the capture, up to about 30 times the bytes of capture read ([SECURITY.md](SECURITY.md#captures-are-untrusted-input)). During the pass a GOOSE stream also keeps every (stNum, sqNum) pair it has seen and a count per second of capture time; they are let go before `Analyze` returns. See [LIMITATIONS.md](LIMITATIONS.md#memory).

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

A skipped range of the TCP stream (a gap: bytes not captured, cut by the snap length or dropped by a reassembly limit) resets the TPKT framing and the TSDU being assembled in that direction and increments `Gaps`. COTP DT user data is appended until a DT with EOT; other TPDU types besides CR, DR and DC carry nothing the library uses. The selectors of a CR are copied into the association.

**Framing.** A TPKT header is the octets 3 and 0 and a length of at least 7. A direction is *synchronised* while every frame follows the one before it: it starts so when its SYN was captured, and each frame is then taken at its length. A frame whose TPDU does not decode is passed over as a whole and counted (`COTPErrors`). The direction is *not synchronised* after a gap, after bytes that are no header, when what it held was given up to the assembly budget, and at the start of a stream whose SYN was not captured. Those four octets can then be data (a three-octet integer with a leading zero, a bit string of three octets), so a header is only a candidate: its length indicator and TPDU code must be those of a TPDU and the TPDU header must fit in the frame and decode (checked as soon as its bytes are there, before the candidate's length is waited for), and the whole TPDU must decode. A candidate that fails costs one byte (`TPKTResync`), so a frame that starts inside the bytes the candidate claimed is still found. The first TPDU that decodes makes the direction synchronised again. Bytes that are no frame are skipped one by one and counted (`TPKTResync`).

## 5. Pairing

Per association and direction, a confirmed request is held by invoke ID until a confirmed response, confirmed error or reject with that invoke ID arrives in the other direction (`ok`, `error`, `reject`). A new request with the invoke ID of a held one makes the held one `unanswered`. A response without a held request becomes an `orphan` transaction. When the connection closes, the requests still held become `unanswered` (and count in `Association.Unanswered`); when the association was not seen closing (end of capture, eviction, a new epoch), they become `pending`. Responses and rejects without an invoke ID, cancel PDUs and initiate and conclude errors are not paired and not counted.

**Pairs across a loss.** A response belongs to the held request for certain only when the capture holds everything the two sides sent between the two: a client that uses an invoke ID again (some always send the same one) may have sent a later request with it that the capture does not hold, and the response then answers that one. The pair is `uncertain` instead of `ok`, `error` or `reject` when either holds:

1. *The requesting direction has a hole since the request was captured.* A hole is a gap of the TCP stream, bytes that were no frame, a TPDU or TSDU that did not decode or was given up. A hole also shows before a gap can be declared for it: the responder's packets acknowledge bytes of the requester that the capture has not delivered (a quiet requester sends nothing after the lost request, so no gap would ever be declared).
2. *The responding direction has a hole since the request was captured* (the request's own response may have been in it, so this response answers a later request), *unless the hole ends before what the requester had acknowledged when it sent the request*: those bytes were sent before the request arrived and cannot hold its response. So a response lost before the next request was sent does not make the next pair uncertain.

Each direction counts its holes and remembers where the last one ended; a request remembers both counts and the acknowledged position of the packet that completed it. The check is a comparison at the response, whatever the number of requests held. What the rule cannot see is in [LIMITATIONS.md](LIMITATIONS.md#mms).

## 6. GOOSE and Sampled Values

Frames of the Ethernet link type (after any 802.1Q, 802.1ad or 0x9100 tags) with EtherType 0x88b8 are decoded with go-iec61850's `goose.Decode`, those with 0x88ba with `sv.Decode`. Other link types are not searched for them. Each GOOSE message is compared with the previous one of its stream ([API.md](API.md#goosestream) lists the issues); each SV ASDU's smpCnt with the previous one of its stream ([API.md](API.md#svstream)). stNum and sqNum are compared as the 32-bit numbers they are, without adding to them. The state after 4294967295 is 1, as go-iec61850 publishes and expects it (its GOOSE.md, "State and sequence numbers"; IEC 61850-7-2 18.2.3.6 starts StNum at 1): that step is a state change, and any other fall of stNum is `stNum decreased`.

## 7. Dependencies

| Module | Used for |
|---|---|
| github.com/otfabric/go-mms v1.11.0 | `mms.DecodeTSDU` and the `mms.Captured*` types; tests also run real go-mms clients and servers (`transport/iso`) to record associations |
| github.com/otfabric/go-cotp v1.4.1 | `cotp.Decode` (it requires go-tpkt v1.2.1) |
| github.com/otfabric/go-iec61850 v1.23.0 | `goose.Decode`, `sv.Decode` |

The library opens no socket and runs no program; `depguard` and `forbidigo` in `.golangci.yml` enforce it for non-test code. go-iec61850's `goose` and `sv` packages also implement live capture and so link `golang.org/x/sys/unix`; the library calls only their decoders ([LIMITATIONS.md](LIMITATIONS.md)).
