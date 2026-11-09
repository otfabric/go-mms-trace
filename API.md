# API

The public API is one package, `github.com/otfabric/go-mms-trace/trace`. Everything under `internal/` is private; the CLI is the nested module `cmd/mmstracectl`.

## Analyze

```go
func Analyze(ctx context.Context, r io.Reader, o Options) (*Result, error)
```

`Analyze` reads a whole capture from `r` (pcap or pcapng, plain or gzip; the format is detected from the first bytes) and returns what it holds. It reads `r` to its end and does not close it. It returns:

- the result and `nil` when the capture was read to its end. A last record cut short is not an error (`File.TruncatedTail` says so);
- the result so far and an error wrapping `ErrCorrupt` when damage ended the read, also a read error of `r` after the file header and a gzip stream whose checksum or length does not match;
- `nil` and an error wrapping `ErrFormat` when the input is not a capture (also an empty input, a pcap header cut short, or an input that starts with the gzip magic but has no valid gzip header);
- `nil` and `ctx.Err()` when the context is cancelled (checked before each packet).

`Analyze` runs in the calling goroutine and starts none. It keeps no state between calls, so calls on different readers can run concurrently (as long as nobody modifies `DefaultPorts`).

```go
type Options struct {
	Ports     []uint16
	MaxPacket int
}
```

`Ports` are the TCP server ports of MMS; `nil` means `DefaultPorts`. An empty non-nil slice matches no port. A TCP segment to or from none of these ports is counted as `other_tcp` in `Counters.Unsupported`. `MaxPacket` bounds a packet record; zero or negative means 256 KiB. A larger record ends a pcap file with `ErrCorrupt` and is skipped in a pcapng file (`File.SkippedBlocks`).

## Constants and variables

| Name | Value | Meaning |
|---|---|---|
| `DefaultPorts` | `[]uint16{102}` | The MMS ports used when `Options.Ports` is nil (ISO-on-TCP). |
| `MaxTSDU` | 16 MiB | Bound of a reassembled transport service data unit; a larger one is dropped and counted in `Counters.TSDUErrors`. |
| `EtherTypeGOOSE` | `0x88b8` | EtherType of GOOSE (IEC 61850-8-1). |
| `EtherTypeSV` | `0x88ba` | EtherType of Sampled Values (IEC 61850-9-2). |
| `StatusOK` ... `StatusPending` | | Transaction statuses, see [Transaction](#transaction). |
| `ErrCorrupt`, `ErrFormat` | | See [ERRORS.md](ERRORS.md). |

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
	Format        string
	Gzip          bool
	SHA256        string
	Packets       uint64
	Interfaces    int
	Links         []string
	InputBytes    int64
	TruncatedTail bool
	SkippedBlocks uint64
	FirstNS       int64
	LastNS        int64
}
```

- `Format` is `pcap` or `pcapng`; `Gzip` says the input was gzip-compressed.
- `SHA256` (hex) and `InputBytes` cover the input bytes as read, the compressed bytes for a gzip input. After a clean end they cover the whole input; after `ErrCorrupt` they cover what was read from `r` up to then, which can include read-ahead past the damage.
- `Packets` counts the packet records read. Frame numbers (`Transaction.RequestFrame`, `Report.Frame`) count as Wireshark numbers frames: pcapng custom and systemd journal blocks take a number too, so the last frame number can exceed `Packets`.
- `Interfaces` and `Links` are the capture's interfaces over all pcapng sections and their link-layer names: `ethernet`, `linux_sll`, `linux_sll2`, `raw`, `ipv4`, `ipv6`, `null`, `loop`, or `other` for a link type the library does not decode.
- `SkippedBlocks` counts damaged pcapng blocks with a plausible length that were skipped.
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
- `CallingTSAP`, `CalledTSAP`: the selectors of the COTP CR, `nil` without one.
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
| `StatusOK` | `ok` | A confirmed response. |
| `StatusError` | `error` | A confirmed error (`Response.Error` has the class and code). |
| `StatusReject` | `reject` | A reject PDU naming the invoke ID. |
| `StatusUnanswered` | `unanswered` | No response before the association ended, or the same invoke ID was used again by a new request first. |
| `StatusOrphan` | `orphan` | A response whose request was not captured. |
| `StatusPending` | `pending` | No response before the capture ended (or before the connection was evicted or superseded). |

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

The GOOSE messages (EtherType 0x88b8, on the Ethernet link type only) of one publisher: one source MAC, APPID and GoCB reference. MACs are lower-case `aa:bb:cc:dd:ee:ff`. `VLAN` is the VLAN ID of the first message, -1 when untagged (0 for a priority tag). `DatSet`, `GoID` and `ConfRev` are those of the last message. `Changes` counts stNum increments. `Simulation` counts messages with the simulation bit (Reserved1 of the GOOSE header) or the test flag of the PDU, `NdsCom` those with ndsCom. `MaxPerSecond` is the most messages within one whole second of capture time (seconds counted from the Unix epoch, not a sliding window).

`Issues` counts, comparing each message with the previous one of the stream:

| Kind | When |
|---|---|
| `stNum decreased` | stNum is lower than before. |
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

`ErrCorrupt` and `ErrFormat`: see [ERRORS.md](ERRORS.md).
