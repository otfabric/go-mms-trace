# API

The public API is one package, `github.com/otfabric/go-mms-trace/trace`. Everything under `internal/` is private; the CLI is the nested module `cmd/mmstracectl`.

## Analyze

```go
func Analyze(ctx context.Context, r io.Reader, o Options) (*Result, error)
```

`Analyze` reads a whole capture from `r` (pcap or pcapng, plain or gzip; the format is detected from the first bytes) and returns what it holds. It reads `r` to its end, or to where an error or a limit ends the read, and does not close it. It returns:

- the result and `nil` when the capture was read to its end. A last record cut short is not an error (`File.TruncatedTail` says so);
- the result so far and an error wrapping `ErrCorrupt` when damage ended the read, also a read error of `r` after the format is known and a gzip stream whose checksum or length does not match. The error also wraps what the reader reported: the error of `r`, or `gzip.ErrChecksum`;
- the result so far and an error wrapping `ErrLimit` when the capture goes on past `Options.MaxBytes`, or has more pcapng sections than `Options.MaxSections`;
- `nil` and an error wrapping `ErrFormat` when the input is not a capture (also an empty input, a pcap header cut short, or an input that starts with the gzip magic but has no valid gzip header). When a read error of `r` ended the read before the format was known, the error wraps that error too;
- `nil` and `ctx.Err()` when the context is done (checked before each packet).

`Analyze` runs in the calling goroutine and starts none. It keeps no state between calls, so calls on different readers can run concurrently (as long as nobody modifies `DefaultPorts`).

**Ownership.** The caller owns the `Result` and everything reachable from it: every slice, map and pointer in it is storage of its own, and `Analyze` keeps no reference to it, to `r` or to bytes read from `r`. The caller may keep and change the result; a later call is not affected.

```go
type Options struct {
	Ports         []uint16
	MaxPacket     int
	MaxBytes      int64
	MaxInterfaces int
	MaxSections   int
	MaxAssembly   int
}
```

The zero value takes every default.

- `Ports` are the TCP server ports of MMS; `nil` means `DefaultPorts`. An empty non-nil slice matches no port. A TCP segment to or from none of these ports is counted as `other_tcp` in `Counters.Unsupported`.
- `MaxPacket` bounds a packet record; zero or negative means 256 KiB. A larger record ends a pcap file with `ErrCorrupt` and is skipped in a pcapng file (`File.SkippedBlocks`). A value above what a record can declare (4 GiB) bounds nothing.
- `MaxBytes` bounds the capture that is read, in bytes after decompression (`File.UncompressedBytes`); zero or negative means `DefaultMaxBytes`. A capture that goes on past it ends the analysis with the result so far and `ErrLimit`: no byte past the limit is read from the capture (the 24 bytes of a pcap file header are read whatever the limit). The memory of a result grows with the capture, so an application that reads captures it does not trust sets this to what it can afford ([SECURITY.md](SECURITY.md)). `math.MaxInt64` bounds nothing.
- `MaxInterfaces` bounds the capture interfaces of a pcapng input, over all its sections; zero or negative means `DefaultMaxInterfaces`. A further interface is skipped together with the packets captured on it (`File.SkippedBlocks`).
- `MaxSections` bounds the sections of a pcapng input; zero or negative means `DefaultMaxSections`. A further section ends the analysis with the result so far and `ErrLimit`.
- `MaxAssembly` bounds the bytes of incomplete TPKT frames and TSDUs held over all connections; zero or negative means `DefaultMaxAssembly`. Beyond it the direction that has waited longest for the rest of its data gives up what it holds: its TSDU is counted in `Counters.TSDUErrors` and its framing starts again (`Counters.TPKTResync`).

## Constants and variables

| Name | Value | Meaning |
|---|---|---|
| `DefaultPorts` | `[]uint16{102}` | The MMS ports used when `Options.Ports` is nil (ISO-on-TCP). |
| `MaxTSDU` | 16 MiB | Bound of a reassembled transport service data unit; a larger one is dropped and counted in `Counters.TSDUErrors`. |
| `DefaultMaxBytes` | 16 GiB (`int64`) | Default of `Options.MaxBytes`. |
| `DefaultMaxInterfaces` | 65,536 | Default of `Options.MaxInterfaces`. |
| `DefaultMaxSections` | 65,536 | Default of `Options.MaxSections`. |
| `DefaultMaxAssembly` | 64 MiB | Default of `Options.MaxAssembly`. |
| `EtherTypeGOOSE` | `0x88b8` | EtherType of GOOSE (IEC 61850-8-1). |
| `EtherTypeSV` | `0x88ba` | EtherType of Sampled Values (IEC 61850-9-2). |
| `StatusOK` ... `StatusUncertain` | | Transaction statuses, see [Transaction](#transaction). |
| `ErrCorrupt`, `ErrFormat`, `ErrLimit` | | See [ERRORS.md](ERRORS.md). |

Why the defaults have these values: [ARCHITECTURE.md](ARCHITECTURE.md#2-limits).

## Result

```go
type Result struct {
	File         File
	Associations []*Association
	Transactions []*Transaction
	Reports      []*Report
	GOOSE        []*GooseStream
	SV           []*SVStream
	Counters     Counters
}
```

`Associations` are in the order their first COTP TPDU was captured. `Transactions` are in the order their first PDU was captured (the request, or the response of an orphan); `Reports` and the streams are in capture order.

### File

```go
type File struct {
	Format            string
	Gzip              bool
	SHA256            string
	Packets           uint64
	Interfaces        int
	Links             []string
	InputBytes        int64
	UncompressedBytes int64
	TruncatedTail     bool
	SkippedBlocks     uint64
	BadTimestamps     uint64
	FirstNS           int64
	LastNS            int64
}
```

- `Format` is `pcap` or `pcapng`; `Gzip` says the input was gzip-compressed.
- `SHA256` (hex) and `InputBytes` cover the input bytes as read, the compressed bytes for a gzip input. After a clean end they cover the whole input; after `ErrCorrupt` or `ErrLimit` they cover what was read from `r` up to then, which can include read-ahead (up to 256 KiB) past where the read ended.
- `UncompressedBytes` is the size of the capture as read: the bytes after decompression of a gzip input, the bytes of a plain one. It is what `Options.MaxBytes` bounds, and equals the limit when the read ended with `ErrLimit` there.
- `Packets` counts the packet records read. Frame numbers (`Transaction.RequestFrame`, `Report.Frame`) count as Wireshark numbers frames: pcapng custom and systemd journal blocks take a number too, so the last frame number can exceed `Packets`.
- `Interfaces` and `Links` are the capture's interfaces over all pcapng sections (at most `Options.MaxInterfaces`) and their link-layer names: `ethernet`, `linux_sll`, `linux_sll2`, `raw`, `ipv4`, `ipv6`, `null`, `loop`, or `other` for a link type the library does not decode.
- `SkippedBlocks` counts pcapng blocks that were skipped: damaged blocks with a plausible length, packets that name no interface, and the interfaces past `Options.MaxInterfaces` with their packets.
- `BadTimestamps` counts the packets of a pcapng file whose time does not fit in 64 bits of nanoseconds (after 2262-04-11 or before 1677-09-21, from the timestamp, the interface's resolution and its offset). They are used without a time, like a packet that has none.
- `FirstNS` and `LastNS` are the times of the first and last packet with a timestamp, Unix nanoseconds; 0 when there is none (pcapng simple packet blocks carry no time).

### Counters

```go
type Counters struct {
	Unsupported map[string]uint64
	TPKTResync  uint64
	COTPErrors  uint64
	TSDUErrors  uint64
	BareMMS     uint64
	TSOSegments uint64
	GOOSEErrors uint64
	SVErrors    uint64
}
```

`Unsupported` is never nil. The meaning of every counter is in [ERRORS.md](ERRORS.md#counters).

### Association

```go
type Association struct {
	ID             int
	Client         netip.AddrPort
	Server         netip.AddrPort
	Open           string
	Close          string
	Accepted       *bool
	Authentication string
	Initiate       *mms.CapturedInitiate
	CallingTSAP    []byte
	CalledTSAP     []byte
	FirstNS        int64
	LastNS         int64
	Transactions   int
	Reports        int
	Unanswered     int
	Gaps           int
}
```

One TCP connection (one epoch of its 4-tuple) on which at least one COTP TPDU decoded. `ID` counts from 1 in that order. `Server` is the end on an MMS port, `Client` the other.

- `Open`: `associate` (AARQ captured), `connect` (COTP CR captured, no AARQ) or `midstream`.
- `Close`: `conclude`, `release`, `abort`, `disconnect` (COTP DR or DC, or TCP FIN in both directions, without an MMS conclude), `reset` (TCP RST), or empty when it was not seen ending. How these are decided: [ARCHITECTURE.md](ARCHITECTURE.md#4-associations).
- `Accepted`: the AARE result (0 is accepted); `nil` when no AARE was decoded.
- `Authentication`: the AARQ's mechanism, `none`, `password` or `other`; empty without an AARQ. Credentials are never decoded.
- `Initiate`: the MMS initiate response, `nil` when none was captured.
- `CallingTSAP`, `CalledTSAP`: the selectors of the COTP CR (copies, owned by the caller), `nil` without one.
- `FirstNS`, `LastNS`: times of the first and last TPDU of the association.
- `Transactions`, `Reports`: how many of each the association has. `Unanswered`: requests that became `unanswered`.
- `Gaps`: how many times bytes of either direction's stream were skipped (not captured, cut by the snap length, or dropped by a reassembly limit); a PDU in a skipped range is not seen.

### Transaction

```go
type Transaction struct {
	Association   int
	InvokeID      uint32
	Service       string
	Status        string
	ServerRequest bool
	Request       *mms.CapturedPDU
	Response      *mms.CapturedPDU
	RequestNS     int64
	ResponseNS    int64
	RequestFrame  uint64
	ResponseFrame uint64
}

func (t *Transaction) LatencyNS() int64
```

A confirmed service: a confirmed request and the confirmed response, confirmed error or reject with the same invoke ID on the same association, sent in the other direction (each side numbers its own requests). `ServerRequest` marks a request the server sent, as during ObtainFile, when the server opens and reads the file from the client. `Service` is go-mms's ISO 9506-2 name (`Read`, `Write`, `GetNameList`, `Kill`, ...; `Service<n>` for a tag it does not define), taken from the request, or from the response of an orphan (then empty for a confirmed error or reject). `Request` and `Response` are `nil` when not captured. `RequestNS` and `ResponseNS` are capture times, 0 when not captured or without a timestamp; frames are packet numbers in the file from 1, 0 when not captured. `LatencyNS` is `ResponseNS - RequestNS`, or -1 when either is 0.

`Status` is one of:

| Constant | Value | Meaning |
|---|---|---|
| `StatusOK` | `ok` | A confirmed response, and the capture holds everything the two sides sent between the request and it. |
| `StatusError` | `error` | A confirmed error (`Response.Error` has the class and code), with the same condition. |
| `StatusReject` | `reject` | A reject PDU naming the invoke ID, with the same condition. |
| `StatusUncertain` | `uncertain` | A confirmed response, confirmed error or reject with the request's invoke ID, while the capture does not hold everything the two sides sent in between. The response may answer a later request with the same invoke ID that was not captured. `Response.Kind` (`confirmed-response`, `confirmed-error`, `reject`) says which of the three it is. |
| `StatusUnanswered` | `unanswered` | No response before the association ended, or the same invoke ID was used again by a new request first. |
| `StatusOrphan` | `orphan` | A response whose request was not captured. |
| `StatusPending` | `pending` | No response before the capture ended (or before the connection was evicted or superseded). |

A pair is `uncertain` in two cases ([ARCHITECTURE.md](ARCHITECTURE.md#5-pairing) has the rule in full): bytes or PDUs of the requesting direction were lost between the request and the response (a gap of the TCP stream, bytes that were no frame, a PDU that did not decode), or the responder had acknowledged bytes of the requester that the capture does not hold; and bytes or PDUs of the responding direction were lost in between, unless the requester had already acknowledged them when it sent the request. `Request`, `Response`, the times and the frames of an uncertain transaction are set as for the other three.

### Report

```go
type Report struct {
	Association int
	TimeNS      int64
	Frame       uint64
	PDU         *mms.CapturedPDU
}
```

An unconfirmed MMS PDU. go-mms decodes every unconfirmed PDU as an InformationReport (`PDU.Service` is `InformationReport`); `PDU.Variables` or `PDU.ListName` name what it reports and `PDU.Values` carry the values. An unconfirmed PDU of another service has `PDU.DecodeError` set.

### GooseStream

```go
type GooseStream struct {
	Src          string
	Dst          string
	AppID        uint16
	VLAN         int
	GocbRef      string
	DatSet       string
	GoID         string
	ConfRev      uint32
	Messages     int
	Changes      int
	FirstNS      int64
	LastNS       int64
	Simulation   int
	NdsCom       int
	Issues       map[string]int
	MaxPerSecond int
}
```

The GOOSE messages (EtherType 0x88b8, on the Ethernet link type only) of one publisher: one source MAC, APPID and GoCB reference. MACs are lower-case `aa:bb:cc:dd:ee:ff`. `VLAN` is the VLAN ID of the first message, -1 when untagged (0 for a priority tag). `DatSet`, `GoID` and `ConfRev` are those of the last message. `Changes` counts stNum increments; the step from 4294967295 to 1 is one (the rollover). `Simulation` counts messages with the simulation bit (Reserved1 of the GOOSE header) or the test flag of the PDU, `NdsCom` those with ndsCom. `MaxPerSecond` is the most messages within one whole second of capture time (seconds counted from the Unix epoch, not a sliding window).

`Issues` counts, comparing each message with the previous one of the stream:

| Kind | When |
|---|---|
| `stNum decreased` | stNum is lower than before, other than by the rollover from 4294967295 to 1. |
| `stNum jumped` | stNum rose by more than one. |
| `sqNum gap` | stNum is the same and sqNum rose by more than one. |
| `repeated (stNum, sqNum)` | The pair was seen before in this stream (at any earlier point). |
| `confRev changed` | confRev differs from the previous message. |
| `entries changed` | numDatSetEntries differs from the previous message. |

### SVStream

```go
type SVStream struct {
	Src      string
	Dst      string
	AppID    uint16
	VLAN     int
	SvID     string
	DatSet   string
	ConfRev  uint32
	Messages int
	ASDUs    int
	Lost     int
	Repeated int
	FirstNS  int64
	LastNS   int64
	Wrap     int
}
```

The Sampled Values ASDUs (EtherType 0x88ba, on the Ethernet link type only) of one publisher: one source MAC, APPID and svID. A frame with several ASDUs adds each to the stream of its svID; `Messages` counts a frame for the stream of its first ASDU. `VLAN` is that of the first frame, -1 when untagged; `DatSet` and `ConfRev` are those of the last ASDU. `ASDUs` counts samples. Each smpCnt is compared with the previous one of the stream: `Lost` adds the values skipped when it rose by more than one, `Repeated` counts an unchanged value, and any fall is taken as a counter wrap and not counted. `Wrap` is the highest smpCnt seen plus one, an estimate of the counter's wrap (the sample rate for a one-second wrap).

## Errors

`ErrCorrupt`, `ErrFormat` and `ErrLimit`: see [ERRORS.md](ERRORS.md).
