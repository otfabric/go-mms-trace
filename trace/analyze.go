// SPDX-License-Identifier: MIT

// Package trace analyses a packet capture (pcap or pcapng, possibly
// gzipped) of IEC 61850 traffic offline: the MMS associations over
// ISO-on-TCP (RFC 1006: TPKT, COTP, session, presentation, ACSE, MMS) with
// their confirmed services paired by invoke ID and their reports, and the
// GOOSE and Sampled Values streams on Ethernet. It never captures live and
// never sends anything.
package trace

import (
	"bytes"
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

// The defaults of the limits in Options.
const (
	// DefaultMaxBytes is the default of Options.MaxBytes: 16 GiB of
	// capture, counted after decompression. An hour of one Sampled Values
	// stream at 4800 frames a second is about 2.5 GiB, and capture tools
	// rotate their files well below this size.
	DefaultMaxBytes int64 = pcapio.DefaultMaxBytes
	// DefaultMaxInterfaces is the default of Options.MaxInterfaces: 65,536
	// capture interfaces over all pcapng sections of one input. A capture
	// has a handful per section.
	DefaultMaxInterfaces = pcapio.DefaultMaxInterfaces
	// DefaultMaxSections is the default of Options.MaxSections: 65,536
	// pcapng sections in one input. A capture has one; captures joined end
	// to end have one each.
	DefaultMaxSections = pcapio.DefaultMaxSections
	// DefaultMaxAssembly is the default of Options.MaxAssembly: 64 MiB of
	// incomplete TPKT frames and TSDUs over all connections, the size of
	// the total buffer for out-of-order TCP segments. An MMS PDU is in
	// assembly only between its first and its last TCP segment.
	DefaultMaxAssembly = 64 << 20
)

// Options configure an analysis. The zero value takes every default.
type Options struct {
	// Ports are the server TCP ports of MMS; nil is DefaultPorts.
	Ports []uint16
	// MaxPacket bounds a packet record; zero or negative is 256 KiB. A
	// value above what a record can declare (4 GiB) bounds nothing.
	MaxPacket int
	// MaxBytes bounds the capture that is read, in bytes after
	// decompression; zero or negative is DefaultMaxBytes. An input that
	// goes on past it ends the analysis with the results so far and an
	// error wrapping ErrLimit. The memory an analysis needs grows with the
	// capture, so an application that reads captures it does not trust
	// sets this to what it can afford (SECURITY.md). math.MaxInt64 bounds
	// nothing.
	MaxBytes int64
	// MaxInterfaces bounds the capture interfaces of a pcapng input, over
	// all its sections; zero or negative is DefaultMaxInterfaces. A further
	// interface is skipped with the packets captured on it
	// (File.SkippedBlocks).
	MaxInterfaces int
	// MaxSections bounds the sections of a pcapng input; zero or negative
	// is DefaultMaxSections. A further section ends the analysis with the
	// results so far and an error wrapping ErrLimit.
	MaxSections int
	// MaxAssembly bounds the bytes of incomplete TPKT frames and TSDUs
	// held over all connections; zero or negative is DefaultMaxAssembly.
	// Beyond it the direction that has waited longest for the rest of its
	// data gives up what it holds: its TSDU counts in
	// Counters.TSDUErrors, and its framing starts again
	// (Counters.TPKTResync).
	MaxAssembly int
}

// ErrCorrupt wraps an error that ended reading a damaged file; the result
// holds what was read before it. The error also wraps what the reader
// reported, down to the error of the caller's io.Reader or of the gzip
// stream.
var ErrCorrupt = errors.New("trace: damaged capture")

// ErrFormat wraps the error of an input that is not a pcap or pcapng file
// (plain or gzip); Analyze then returns no result. When the input could not
// be read far enough to tell, the error also wraps the error of the
// caller's io.Reader.
var ErrFormat = pcapio.ErrFormat

// ErrLimit wraps the error of an input that goes on past Options.MaxBytes
// or has more pcapng sections than Options.MaxSections; the result holds
// what was read before it.
var ErrLimit = pcapio.ErrLimit

// Analyze reads a whole capture and returns what it holds. A damaged file
// ends the analysis with the results so far and an error wrapping
// ErrCorrupt, an input beyond Options.MaxBytes or Options.MaxSections with
// the results so far and an error wrapping ErrLimit. Cancelling ctx stops
// it between packets.
//
// The caller owns the Result and everything reachable from it: Analyze
// keeps no reference to it, to r or to anything read from r, and no state
// between calls.
func Analyze(ctx context.Context, r io.Reader, o Options) (*Result, error) {
	if o.Ports == nil {
		o.Ports = DefaultPorts
	}
	if o.MaxAssembly <= 0 {
		o.MaxAssembly = DefaultMaxAssembly
	}
	rd, err := pcapio.NewReader(r, pcapio.Options{MaxPacket: o.MaxPacket, MaxBytes: o.MaxBytes,
		MaxInterfaces: o.MaxInterfaces, MaxSections: o.MaxSections})
	if err != nil {
		return nil, err
	}
	a := newAnalyzer(o)
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
			if errors.Is(err, ErrLimit) {
				readErr = err
			} else if !errors.Is(err, io.EOF) {
				readErr = fmt.Errorf("%w: %w", ErrCorrupt, err)
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
	f.InputBytes, f.UncompressedBytes = rd.InputBytes(), rd.Offset()
	f.TruncatedTail, f.SkippedBlocks, f.BadTimestamps = rc.TruncatedTail, rc.SkippedBlocks, rc.BadTimestamps
	if len(a.res.Counters.Unsupported) == 0 {
		a.res.Counters.Unsupported = map[string]uint64{}
	}
	// What a stream needed only to compare its messages is not part of the
	// result.
	for _, s := range a.res.GOOSE {
		s.last, s.seen, s.perSecond = nil, nil, nil
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
	// held is the list of the directions that hold bytes of an incomplete
	// TPKT or TSDU, the one fed longest ago first (held.next), and heldLen
	// what they hold in all: at most Options.MaxAssembly.
	held    isoDir
	heldLen int
}

// newAnalyzer returns the handler of one analysis. o has its defaults.
func newAnalyzer(o Options) *analyzer {
	a := &analyzer{o: o, res: &Result{Counters: Counters{Unsupported: map[string]uint64{}}},
		gooseByKey: map[string]*GooseStream{}, svByKey: map[string]*SVStream{}}
	a.held.prev, a.held.next = &a.held, &a.held
	return a
}

// conn is the ISO stack state of one TCP connection.
type conn struct {
	assoc   *Association
	server  int // direction index of the server: the end on an MMS port
	dirs    [2]isoDir
	pending map[pendingKey]request
}

// pendingKey is a request waiting for its answer: the direction that sent
// it and its invoke ID.
type pendingKey struct {
	dir int
	id  uint32
}

// request is a confirmed request waiting for its answer, with what decides
// later whether the capture holds everything the two sides sent between
// the request and its answer: the holes of its own direction (sent) and of
// the direction its answer comes in (back) when it was captured, and the
// position of that direction its sender had acknowledged then (acked, when
// hasAcked).
type request struct {
	t          *Transaction
	sent, back uint64
	acked      uint64
	hasAcked   bool
}

// isoDir reassembles one direction: TPKT frames from the byte stream, the
// user data of COTP DT TPDUs into TSDUs.
type isoDir struct {
	buf      []byte
	tsdu     []byte
	tsduOver bool
	// started says the direction delivered bytes or skipped some. lost
	// says its TPKT framing is not synchronised: bytes were skipped, or
	// the capture did not hold the start of the stream. Until a TPDU
	// decodes again, a TPKT header is a candidate that may be data.
	started, lost bool
	// end is the stream position the direction has reached: delivered or
	// skipped. holes counts the times bytes or PDUs of this direction were
	// lost to the analysis: a gap of the TCP stream, bytes skipped to find
	// a TPKT header, a TPDU or TSDU that did not decode or was given up.
	// holeEnd is the position the direction had reached at the last one.
	end, holes, holeEnd uint64
	// first frame and time of the TSDU being assembled
	frame uint64
	ns    int64
	// charged is what the direction holds of Options.MaxAssembly; prev and
	// next link it into the analyzer's list while it holds something.
	charged    int
	prev, next *isoDir
}

// Open implements flow.Handler.
func (a *analyzer) Open(c *flow.Conn) {
	// Only segments to or from an MMS port reach the tracker.
	cs := &conn{pending: map[pendingKey]request{}}
	if !slices.Contains(a.o.Ports, c.Endpoints[0].Port()) {
		cs.server = 1
	}
	c.User = cs
}

// Repeat implements flow.Handler: retransmitted bytes were delivered once.
func (a *analyzer) Repeat(*flow.Conn, int, uint64, uint64) {}

// Gap implements flow.Handler: bytes are missing, so the TPKT framing and
// the TSDU being assembled in that direction start again.
func (a *analyzer) Gap(c *flow.Conn, dir int, pos uint64, n int64, _ flow.GapKind) {
	cs := c.User.(*conn)
	if cs.assoc != nil {
		cs.assoc.Gaps++
	}
	d := &cs.dirs[dir]
	d.end = pos + uint64(n)
	a.reset(d)
}

// hole records that bytes or PDUs of the direction were lost to the
// analysis, up to the position it has reached.
func (d *isoDir) hole() {
	d.holes++
	d.holeEnd = d.end
}

// reset starts the direction again after bytes of it were lost: what it
// held is let go, its framing is not synchronised, and it has one more
// hole.
func (a *analyzer) reset(d *isoDir) {
	a.unhold(d)
	*d = isoDir{started: true, lost: true, end: d.end, holes: d.holes, holeEnd: d.holeEnd}
	d.hole()
}

// unhold takes the direction out of the list of holders.
func (a *analyzer) unhold(d *isoDir) {
	a.heldLen -= d.charged
	d.charged = 0
	if d.next != nil {
		d.prev.next, d.next.prev = d.next, d.prev
		d.prev, d.next = nil, nil
	}
}

// account charges what the direction holds now, after it was fed, and
// keeps the total within Options.MaxAssembly: beyond it, the direction fed
// longest ago gives up what it holds, until the total fits. Each step is a
// constant amount of work, whatever the number of connections.
func (a *analyzer) account(d *isoDir) {
	n := cap(d.buf) + cap(d.tsdu)
	a.unhold(d)
	if n == 0 {
		return
	}
	d.charged = n
	a.heldLen += n
	d.prev, d.next = a.held.prev, &a.held
	a.held.prev.next = d
	a.held.prev = d
	for a.heldLen > a.o.MaxAssembly {
		v := a.held.next
		a.res.Counters.TPKTResync += uint64(len(v.buf))
		over := v.tsduOver || len(v.tsdu) > 0
		a.reset(v)
		v.tsduOver = over // the rest of its TSDU is not assembled; its end counts it
	}
}

// Close implements flow.Handler.
func (a *analyzer) Close(c *flow.Conn) {
	cs := c.User.(*conn)
	for d := range cs.dirs {
		// The connection delivers nothing more: its buffers are let go.
		a.unhold(&cs.dirs[d])
		cs.dirs[d] = isoDir{}
	}
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
	for id, r := range cs.pending {
		r.t.Status = status
		if status == StatusUnanswered {
			cs.assoc.Unanswered++
		}
		delete(cs.pending, id)
	}
}

// Data implements flow.Handler. b is the tracker's: what is kept of it is
// copied.
func (a *analyzer) Data(c *flow.Conn, dir int, pos uint64, b []byte, ch flow.Chunk) {
	cs := c.User.(*conn)
	d := &cs.dirs[dir]
	if !d.started {
		// A direction whose SYN was captured starts at a TPKT header; any
		// other may start inside a TPKT.
		d.started, d.lost = true, c.SYNFrom != dir && c.SYNACKFrom != dir
	}
	d.end = pos + uint64(len(b))
	buf := b
	if len(d.buf) > 0 {
		d.buf = append(d.buf, b...)
		buf = d.buf
	}
	rest := a.frames(c, cs, dir, buf, ch)
	switch {
	case len(rest) == 0:
		d.buf = nil
	case len(d.buf) > 0 && len(rest) == len(buf):
		// Nothing was taken from the direction's own buffer: it waits for
		// the rest of its TPKT.
	default:
		// A copy of its own size: b is not ours to keep, and the bytes
		// taken from the front of the buffer are let go.
		d.buf = bytes.Clone(rest)
	}
	a.account(d)
}

// skip drops n bytes that are not part of a TPKT frame from buf: the
// direction is not synchronised until a TPDU decodes again.
func (a *analyzer) skip(d *isoDir, buf []byte, n int) []byte {
	a.res.Counters.TPKTResync += uint64(n)
	d.lost = true
	d.hole()
	return buf[n:]
}

// frames takes the complete TPKT frames out of buf, the bytes of one
// direction from its last frame on, and returns what is left: the start of
// a frame that is not complete yet.
//
// A TPKT header is 3, 0 and a length of at least 7. While the direction is
// synchronised, the frame that follows a frame is taken at its length.
// While it is not (after a gap of the stream, after bytes that were no
// header, at the start of a stream captured midstream), those four bytes
// may be data, so a header is only a candidate: it is accepted when its
// COTP TPDU decodes, and otherwise costs one byte, so that a frame that
// starts inside the bytes it claims is still found.
func (a *analyzer) frames(c *flow.Conn, cs *conn, dir int, buf []byte, ch flow.Chunk) []byte {
	d := &cs.dirs[dir]
	for len(buf) >= 4 {
		if buf[0] != 3 || buf[1] != 0 {
			// Not a TPKT header: find the next one.
			i := 1
			for i < len(buf)-1 && (buf[i] != 3 || buf[i+1] != 0) {
				i++
			}
			buf = a.skip(d, buf, i)
			continue
		}
		n := int(binary.BigEndian.Uint16(buf[2:4]))
		if n < 7 {
			buf = a.skip(d, buf, 1)
			continue
		}
		if d.lost {
			// Before waiting for the bytes a candidate claims: the TPDU
			// header it would start with has to be one, and to fit.
			if len(buf) < 6 {
				break
			}
			h := 5 + int(buf[4]) // the end of the TPDU header its length indicator gives
			typ, err := cotp.PeekType(buf[4:6])
			if err != nil || h > n {
				buf = a.skip(d, buf, 1)
				continue
			}
			if len(buf) < h {
				break
			}
			// The header alone decodes when it is one, except for
			// expedited data, which cannot be empty.
			if typ != cotp.TypeED {
				if _, err := cotp.Decode(buf[4:h]); err != nil {
					buf = a.skip(d, buf, 1)
					continue
				}
			}
		}
		if len(buf) < n {
			break
		}
		t, err := cotp.Decode(buf[4:n])
		switch {
		case err == nil:
			d.lost = false
			a.tpdu(c, cs, dir, &t, ch)
		case d.lost:
			buf = a.skip(d, buf, 1)
			continue
		default:
			a.res.Counters.COTPErrors++
			d.hole()
		}
		buf = buf[n:]
	}
	return buf
}

// tpdu handles one COTP TPDU.
func (a *analyzer) tpdu(c *flow.Conn, cs *conn, dir int, t *cotp.Decoded, ch flow.Chunk) {
	as := a.association(c, cs, ch)
	switch {
	case t.CR != nil:
		if as.Open == "midstream" {
			as.Open = "connect"
		}
		// Copies: the decoded selectors point into the bytes they were
		// decoded from, which are not kept.
		as.CallingTSAP, as.CalledTSAP = bytes.Clone(t.CR.CallingSelector), bytes.Clone(t.CR.CalledSelector)
	case t.DT != nil:
		d := &cs.dirs[dir]
		if len(d.tsdu) == 0 {
			d.frame, d.ns = ch.Frame, ch.TimeNS
		}
		if d.tsduOver || len(d.tsdu)+len(t.DT.UserData) > maxTSDU {
			d.tsduOver, d.tsdu = true, nil
		} else {
			d.tsdu = append(d.tsdu, t.DT.UserData...)
		}
		if t.DT.EOT {
			if d.tsduOver {
				a.res.Counters.TSDUErrors++
				d.hole()
			} else {
				a.tsdu(c, cs, dir, d.tsdu, d.frame, d.ns, ch)
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

// uncertain reports whether an answer in direction dir, with the invoke ID
// of the waiting request r, may answer another request. The answer belongs
// to r for certain only when the capture holds everything the two sides
// sent in between:
//
//   - A hole in the requesting direction since r was captured may have held
//     a later request with the same invoke ID, the one this answers. Such a
//     hole shows before a gap can be declared for it: the answering side
//     has acknowledged bytes of the requesting side that the capture has
//     not delivered.
//   - A hole in the answering direction since r was captured may have held
//     r's own answer, so that this one answers a later request. That cannot
//     be when the hole ends before the position the requester had
//     acknowledged when it sent r: those bytes were sent before r arrived.
func (a *analyzer) uncertain(c *flow.Conn, cs *conn, dir int, r request) bool {
	req, ans := &cs.dirs[1-dir], &cs.dirs[dir]
	if req.holes != r.sent || c.AckedAhead(1-dir) {
		return true
	}
	return ans.holes != r.back && (!r.hasAcked || ans.holeEnd > r.acked)
}

// tsdu handles one reassembled TSDU: its first frame and time, and the
// chunk that completed it.
func (a *analyzer) tsdu(c *flow.Conn, cs *conn, dir int, b []byte, frame uint64, ns int64, ch flow.Chunk) {
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
		cs.dirs[dir].hole()
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
		if old, ok := cs.pending[k]; ok {
			old.t.Status = StatusUnanswered // the invoke ID was used again before an answer
			as.Unanswered++
		}
		cs.pending[k] = request{t: t, sent: cs.dirs[dir].holes, back: cs.dirs[1-dir].holes, acked: ch.Acked, hasAcked: ch.HasAcked}
		as.Transactions++
		a.res.Transactions = append(a.res.Transactions, t)
	case "confirmed-response", "confirmed-error", "reject":
		if !p.HasInvokeID {
			return
		}
		k := pendingKey{1 - dir, p.InvokeID}
		var t *Transaction
		if r, ok := cs.pending[k]; ok {
			delete(cs.pending, k)
			t = r.t
			t.Status = map[string]string{"confirmed-response": StatusOK, "confirmed-error": StatusError, "reject": StatusReject}[p.Kind]
			if a.uncertain(c, cs, dir, r) {
				t.Status = StatusUncertain
			}
		} else {
			t = &Transaction{Association: as.ID, InvokeID: p.InvokeID, Service: p.Service, Status: StatusOrphan, ServerRequest: dir != cs.server}
			as.Transactions++
			a.res.Transactions = append(a.res.Transactions, t)
		}
		t.Response, t.ResponseNS, t.ResponseFrame = p, ns, frame
	case "unconfirmed":
		as.Reports++
		a.res.Reports = append(a.res.Reports, &Report{Association: as.ID, TimeNS: ns, Frame: frame, PDU: p})
	case "conclude-request", "conclude-response":
		as.Close = "conclude"
	}
}
