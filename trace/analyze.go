// SPDX-License-Identifier: MIT

// Package trace analyses a packet capture (pcap or pcapng, possibly
// gzipped) of IEC 61850 traffic offline: the MMS associations over
// ISO-on-TCP (RFC 1006: TPKT, COTP, session, presentation, ACSE, MMS) with
// their confirmed services paired by invoke ID and their reports, and the
// GOOSE and Sampled Values streams on Ethernet. It never captures live and
// never sends anything.
package trace

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/otfabric/go-cotp"
	mms "github.com/otfabric/go-mms"

	"github.com/otfabric/go-mms-trace/internal/flow"
	"github.com/otfabric/go-mms-trace/internal/link"
	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// DefaultPorts are the TCP ports MMS is looked for on: 102 (ISO-on-TCP).
// MMS over TLS (port 3782) is encrypted and cannot be decoded.
var DefaultPorts = []uint16{102}

// MaxTSDU bounds a reassembled transport service data unit; a larger one is
// dropped and counted.
const MaxTSDU = 16 << 20

// maxTSDU is MaxTSDU; tests lower it.
var maxTSDU = MaxTSDU

// Options configure an analysis.
type Options struct {
	// Ports are the server TCP ports of MMS; nil is DefaultPorts.
	Ports []uint16
	// MaxPacket bounds a packet record; zero is the reader's default.
	MaxPacket int
}

// ErrCorrupt wraps an error that ended reading a damaged file; the result
// holds what was read before it.
var ErrCorrupt = errors.New("trace: damaged capture")

// ErrFormat wraps the error of an input that is not a pcap or pcapng file
// (plain or gzip); Analyze then returns no result.
var ErrFormat = pcapio.ErrFormat

// Analyze reads a whole capture and returns what it holds. A damaged file
// ends the analysis with the results so far and an error wrapping
// ErrCorrupt. Cancelling ctx stops it between packets.
func Analyze(ctx context.Context, r io.Reader, o Options) (*Result, error) {
	if o.Ports == nil {
		o.Ports = DefaultPorts
	}
	rd, err := pcapio.NewReader(r, pcapio.Options{MaxPacket: o.MaxPacket})
	if err != nil {
		return nil, err
	}
	a := &analyzer{o: o, res: &Result{Counters: Counters{Unsupported: map[string]uint64{}}},
		gooseByKey: map[string]*GooseStream{}, svByKey: map[string]*SVStream{}}
	dec := link.NewDecoder(1 << 20)
	tr := flow.NewTracker(flow.DefaultLimits, a)
	var p pcapio.Packet
	var seg link.Segment
	var readErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := rd.Next(&p); err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = fmt.Errorf("%w: %v", ErrCorrupt, err)
			}
			break
		}
		f := &a.res.File
		f.Packets++
		if p.HasTime {
			if f.FirstNS == 0 {
				f.FirstNS = p.TimeNS
			}
			f.LastNS = p.TimeNS
		}
		a.frame, a.ns = p.Frame, p.TimeNS
		if p.LinkType == link.LinkEthernet {
			if et, ok := etherType(p.Data); ok && (et == EtherTypeGOOSE || et == EtherTypeSV) {
				if et == EtherTypeGOOSE {
					a.goose(p.Data, p.TimeNS)
				} else {
					a.sv(p.Data, p.TimeNS)
				}
				continue
			}
		}
		if reason := dec.Decode(p.LinkType, p.Data, &seg); reason != link.OK {
			if reason != link.FragmentHeld {
				a.res.Counters.Unsupported[reason.String()]++
			}
			continue
		}
		if !slices.Contains(o.Ports, seg.Src.Port()) && !slices.Contains(o.Ports, seg.Dst.Port()) {
			a.res.Counters.Unsupported["other_tcp"]++
			continue
		}
		tr.Packet(&p, &seg)
	}
	tr.Finish()
	a.res.Counters.TSOSegments = dec.TSO
	sum := rd.SHA256()
	f := &a.res.File
	f.Format, f.Gzip, f.SHA256, f.Interfaces = rd.Format().String(), rd.Gzip(), hex.EncodeToString(sum[:]), len(rd.Interfaces())
	f.Links = make([]string, 0, len(rd.Interfaces()))
	for _, i := range rd.Interfaces() {
		f.Links = append(f.Links, link.LinkName(i.LinkType))
	}
	rc := rd.Counters()
	f.InputBytes, f.TruncatedTail, f.SkippedBlocks = rd.InputBytes(), rc.TruncatedTail, rc.SkippedBlocks
	if len(a.res.Counters.Unsupported) == 0 {
		a.res.Counters.Unsupported = map[string]uint64{}
	}
	return a.res, readErr
}

// etherType returns the EtherType of an Ethernet II frame after any 802.1Q
// or QinQ tags.
func etherType(b []byte) (uint16, bool) {
	off := 12
	for {
		if len(b) < off+2 {
			return 0, false
		}
		et := binary.BigEndian.Uint16(b[off:])
		if et != 0x8100 && et != 0x88a8 && et != 0x9100 {
			return et, true
		}
		off += 4
	}
}

type analyzer struct {
	o          Options
	res        *Result
	frame      uint64
	ns         int64
	gooseByKey map[string]*GooseStream
	svByKey    map[string]*SVStream
}

// conn is the ISO stack state of one TCP connection.
type conn struct {
	assoc   *Association
	server  int // direction index of the server: the end on an MMS port
	dirs    [2]isoDir
	pending map[pendingKey]*Transaction
}

// pendingKey is a request waiting for its answer: the direction that sent
// it and its invoke ID.
type pendingKey struct {
	dir int
	id  uint32
}

// isoDir reassembles one direction: TPKT frames from the byte stream, the
// user data of COTP DT TPDUs into TSDUs.
type isoDir struct {
	buf      []byte
	tsdu     []byte
	tsduOver bool
	// first frame and time of the TSDU being assembled
	frame uint64
	ns    int64
}

// Open implements flow.Handler.
func (a *analyzer) Open(c *flow.Conn) {
	// Only segments to or from an MMS port reach the tracker.
	cs := &conn{pending: map[pendingKey]*Transaction{}}
	if !slices.Contains(a.o.Ports, c.Endpoints[0].Port()) {
		cs.server = 1
	}
	c.User = cs
}

// Repeat implements flow.Handler: retransmitted bytes were delivered once.
func (a *analyzer) Repeat(*flow.Conn, int, uint64, uint64) {}

// Gap implements flow.Handler: bytes are missing, so the TPKT framing and
// the TSDU being assembled in that direction start again.
func (a *analyzer) Gap(c *flow.Conn, dir int, _ uint64, _ int64, _ flow.GapKind) {
	cs := c.User.(*conn)
	if cs.assoc != nil {
		cs.assoc.Gaps++
	}
	cs.dirs[dir] = isoDir{}
}

// Close implements flow.Handler.
func (a *analyzer) Close(c *flow.Conn) {
	cs := c.User.(*conn)
	if cs.assoc == nil {
		return
	}
	if cs.assoc.Close == "" {
		switch c.Close {
		case flow.CloseFIN:
			cs.assoc.Close = "disconnect"
		case flow.CloseRST:
			cs.assoc.Close = "reset"
		case flow.Live, flow.CloseEnd, flow.CloseEvict, flow.CloseSuper:
			// Not seen closing (the capture ended, or tracking gave the
			// connection up): the association stays open.
		}
	}
	a.finish(cs)
}

// finish marks the requests still waiting: unanswered when the
// association ended, pending when the trace ended first.
func (a *analyzer) finish(cs *conn) {
	status := StatusUnanswered
	if cs.assoc.Close == "" {
		status = StatusPending
	}
	for id, t := range cs.pending {
		t.Status = status
		if status == StatusUnanswered {
			cs.assoc.Unanswered++
		}
		delete(cs.pending, id)
	}
}

// Data implements flow.Handler.
func (a *analyzer) Data(c *flow.Conn, dir int, _ uint64, b []byte, ch flow.Chunk) {
	cs := c.User.(*conn)
	d := &cs.dirs[dir]
	d.buf = append(d.buf, b...)
	for {
		if len(d.buf) < 4 {
			return
		}
		if d.buf[0] != 3 || d.buf[1] != 0 {
			// Not a TPKT header: find the next one.
			i := 1
			for i < len(d.buf)-1 && (d.buf[i] != 3 || d.buf[i+1] != 0) {
				i++
			}
			a.res.Counters.TPKTResync += uint64(i)
			d.buf = d.buf[i:]
			continue
		}
		n := int(binary.BigEndian.Uint16(d.buf[2:4]))
		if n < 7 {
			a.res.Counters.TPKTResync++
			d.buf = d.buf[1:]
			continue
		}
		if len(d.buf) < n {
			return
		}
		a.tpdu(c, cs, dir, d.buf[4:n], ch)
		d.buf = d.buf[n:]
	}
}

// tpdu handles one COTP TPDU.
func (a *analyzer) tpdu(c *flow.Conn, cs *conn, dir int, b []byte, ch flow.Chunk) {
	t, err := cotp.Decode(b)
	if err != nil {
		a.res.Counters.COTPErrors++
		return
	}
	as := a.association(c, cs, ch)
	switch {
	case t.CR != nil:
		if as.Open == "midstream" {
			as.Open = "connect"
		}
		as.CallingTSAP, as.CalledTSAP = t.CR.CallingSelector, t.CR.CalledSelector
	case t.DT != nil:
		d := &cs.dirs[dir]
		if len(d.tsdu) == 0 {
			d.frame, d.ns = ch.Frame, ch.TimeNS
		}
		if len(d.tsdu)+len(t.DT.UserData) > maxTSDU {
			d.tsduOver = true
		} else {
			d.tsdu = append(d.tsdu, t.DT.UserData...)
		}
		if t.DT.EOT {
			if d.tsduOver {
				a.res.Counters.TSDUErrors++
			} else {
				a.tsdu(c, cs, dir, d.tsdu, d.frame, d.ns)
			}
			d.tsdu, d.tsduOver = nil, false
		}
	case t.DR != nil, t.DC != nil:
		if as.Close == "" {
			as.Close = "disconnect"
		}
	}
}

func (a *analyzer) association(c *flow.Conn, cs *conn, ch flow.Chunk) *Association {
	if cs.assoc == nil {
		cs.assoc = &Association{ID: len(a.res.Associations) + 1, Open: "midstream", FirstNS: ch.TimeNS}
		cs.assoc.Server, cs.assoc.Client = c.Endpoints[cs.server], c.Endpoints[1-cs.server]
		a.res.Associations = append(a.res.Associations, cs.assoc)
	}
	cs.assoc.LastNS = ch.TimeNS
	return cs.assoc
}

// tsdu handles one reassembled TSDU.
func (a *analyzer) tsdu(c *flow.Conn, cs *conn, dir int, b []byte, frame uint64, ns int64) {
	as := cs.assoc
	u, err := mms.DecodeTSDU(b)
	if errors.Is(err, mms.ErrNotMMS) {
		// Not a session SPDU: some tools put the MMS PDU straight into
		// COTP, without session, presentation and ACSE (Wireshark decodes
		// that too). IEC 61850-8-1 never does.
		if p, perr := mms.DecodePDU(b); perr == nil {
			u, err = &mms.Captured{PDU: p}, nil
			a.res.Counters.BareMMS++
		}
	}
	if err != nil {
		a.res.Counters.TSDUErrors++
		if u == nil {
			return
		}
	}
	if u.Session == "abort" {
		as.Close = "abort"
	}
	if x := u.ACSE; x != nil {
		switch x.Kind {
		case "AARQ":
			as.Open = "associate"
			as.Authentication = x.Authentication
		case "AARE":
			if x.Result != nil {
				ok := *x.Result == 0
				as.Accepted = &ok
			}
		case "RLRQ", "RLRE":
			if as.Close == "" || as.Close == "conclude" {
				as.Close = "release"
			}
		case "ABRT":
			as.Close = "abort"
		}
	}
	p := u.PDU
	if p == nil {
		return
	}
	switch p.Kind {
	case "initiate-response":
		as.Initiate = p.Initiate
	case "confirmed-request":
		// Each side numbers its own requests: a server that runs
		// ObtainFile opens and reads the file from the client with
		// invoke IDs of its own.
		t := &Transaction{Association: as.ID, InvokeID: p.InvokeID, Service: p.Service, Request: p, RequestNS: ns, RequestFrame: frame,
			ServerRequest: dir == cs.server}
		k := pendingKey{dir, p.InvokeID}
		if old := cs.pending[k]; old != nil {
			old.Status = StatusUnanswered // the invoke ID was used again before an answer
			as.Unanswered++
		}
		cs.pending[k] = t
		as.Transactions++
		a.res.Transactions = append(a.res.Transactions, t)
	case "confirmed-response", "confirmed-error", "reject":
		if !p.HasInvokeID {
			return
		}
		k := pendingKey{1 - dir, p.InvokeID}
		t := cs.pending[k]
		if t == nil {
			t = &Transaction{Association: as.ID, InvokeID: p.InvokeID, Service: p.Service, Status: StatusOrphan, ServerRequest: dir != cs.server}
			as.Transactions++
			a.res.Transactions = append(a.res.Transactions, t)
		} else {
			delete(cs.pending, k)
			t.Status = map[string]string{"confirmed-response": StatusOK, "confirmed-error": StatusError, "reject": StatusReject}[p.Kind]
		}
		t.Response, t.ResponseNS, t.ResponseFrame = p, ns, frame
	case "unconfirmed":
		as.Reports++
		a.res.Reports = append(a.res.Reports, &Report{Association: as.ID, TimeNS: ns, Frame: frame, PDU: p})
	case "conclude-request", "conclude-response":
		as.Close = "conclude"
	}
}
