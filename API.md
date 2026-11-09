# API

The public API is one package, `github.com/otfabric/go-mms-trace/trace`. Everything under `internal/` is private; the CLI is the nested module `cmd/mmstracectl`.

## Analyze

```go
func Analyze(ctx context.Context, r io.Reader, o Options) (*Result, error)
```

`Analyze` reads a whole capture from `r` (pcap or pcapng, plain or gzip) and returns what it holds. It returns:

- the result and `nil` when the capture was read to its end (a last record cut short is not an error: `File.TruncatedTail` says so);
- the result so far and an error wrapping `ErrCorrupt` when damage ended the read;
- `nil` and an error wrapping `ErrFormat` when the input is not a capture;
- `nil` and `ctx.Err()` when the context is cancelled (checked between packets).

```go
type Options struct {
	Ports     []uint16
	MaxPacket int
}
```

`Ports` are the TCP server ports of MMS; `nil` means `DefaultPorts` (`[]uint16{102}`). A TCP segment to or from none of these ports is counted as `other_tcp` in `Counters.Unsupported`. `MaxPacket` bounds a packet record (zero: 256 KiB); a larger record is damage.

`MaxTSDU` (16 MiB) bounds a reassembled transport service data unit; a larger one is dropped and counted in `Counters.TSDUErrors`.

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

`Transactions` are in the order their first PDU was captured; `Reports` and the streams in capture order.

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

`Format` is `pcap` or `pcapng`; `SHA256` is the hash of the uncompressed stream as read. `Links` are the link-layer names of the interfaces (`ethernet`, `linux_sll`, `linux_sll2`, `raw`, `ipv4`, `ipv6`, `null`, `loop`, `other`). `SkippedBlocks` counts damaged pcapng blocks that were skipped. Times are Unix nanoseconds.

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

The meaning of every counter is in [ERRORS.md](ERRORS.md).

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

One TCP connection on which the ISO stack carried at least one COTP TPDU. `ID` counts from 1. `Server` is the end on an MMS port.

- `Open`: `associate` (AARQ captured), `connect` (COTP CR captured, no AARQ) or `midstream`.
- `Close`: `conclude`, `release`, `abort`, `disconnect` (COTP DR or DC, or TCP FIN, without an MMS conclude), `reset` (TCP RST), or empty when still open at the end of the capture.
- `Accepted`: the AARE result, `nil` when no AARE was captured.
- `Authentication`: the AARQ's mechanism, `none`, `password` or `other`. Credentials are never decoded.
- `Gaps`: holes in either direction's byte stream; a PDU in a hole is not seen.

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

A confirmed service: a confirmed request and the confirmed response, confirmed error or reject with the same invoke ID on the same association, in the other direction (each side numbers its own requests). `ServerRequest` marks a request the server sent, as during ObtainFile, when the server opens and reads the file from the client. `Service` is go-mms's ISO 9506-2 name (`Read`, `Write`, `GetNameList`, `Kill`, ...). `Response` is `nil` while none was captured. Frames are packet numbers in the file, from 1; 0 means not captured. `LatencyNS` is `ResponseNS - RequestNS`, or -1 when either is missing.

`Status` is one of:

| Constant | Value | Meaning |
|---|---|---|
| `StatusOK` | `ok` | A confirmed response. |
| `StatusError` | `error` | A confirmed error (`Response.Error` has the class and code). |
| `StatusReject` | `reject` | A reject PDU naming the invoke ID. |
| `StatusUnanswered` | `unanswered` | No response before the association ended. |
| `StatusOrphan` | `orphan` | A response whose request was not captured. |
| `StatusPending` | `pending` | No response before the capture ended. |

### Report

```go
type Report struct {
	Association int
	TimeNS      int64
	Frame       uint64
	PDU         *mms.CapturedPDU
}
```

An unconfirmed InformationReport; `PDU.Variables` or `PDU.ListName` name what it reports, `PDU.Values` carry the values.

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

The GOOSE messages (EtherType `EtherTypeGOOSE`, 0x88b8) of one publisher: one source MAC, APPID and GoCB reference. `VLAN` is -1 when untagged. `Changes` counts stNum increments. `Simulation` counts messages with the simulation bit or the test flag, `NdsCom` those with ndsCom. `MaxPerSecond` is the most messages in one second of capture time. `Issues` counts by kind: `stNum decreased`, `stNum jumped` (by more than one), `sqNum gap`, `repeated (stNum, sqNum)`, `confRev changed`, `entries changed`.

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

The Sampled Values (EtherType `EtherTypeSV`, 0x88ba) of one publisher: one source MAC, APPID and svID. `ASDUs` counts samples; `Lost` counts smpCnt values skipped (a counter wrap is not counted), `Repeated` those seen twice in a row. `Wrap` is the highest smpCnt seen plus one, an estimate of the counter's wrap.

## Errors

`ErrCorrupt` and `ErrFormat`: see [ERRORS.md](ERRORS.md).
