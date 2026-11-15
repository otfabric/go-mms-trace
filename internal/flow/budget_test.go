// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"math/bits"
	"net/netip"
	"runtime"
	"testing"

	"github.com/otfabric/go-mms-trace/internal/link"
	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// counter is a Handler that counts what it is given.
type counter struct {
	data, gaps, repeats int
	gapBytes            int64
}

func (h *counter) Open(*Conn)                                       {}
func (h *counter) Data(_ *Conn, _ int, _ uint64, b []byte, _ Chunk) { h.data += len(b) }
func (h *counter) Repeat(*Conn, int, uint64, uint64)                { h.repeats++ }
func (h *counter) Gap(_ *Conn, _ int, _ uint64, n int64, _ GapKind) {
	h.gaps++
	h.gapBytes += n
}
func (h *counter) Close(*Conn) {}

var (
	clAddr = netip.MustParseAddrPort(cl)
	svAddr = netip.MustParseAddrPort(sv)
)

// segment feeds one segment from src to dst.
func segment(t *Tracker, src, dst netip.AddrPort, seq, ack uint32, flags uint8, payload []byte) *Conn {
	s := link.Segment{Src: src, Dst: dst, Seq: seq, Ack: ack, Flags: flags, Payload: payload}
	return t.Packet(&pcapio.Packet{Frame: 1, HasTime: true, TimeNS: 1}, &s)
}

// TestOldSegmentDistances: a segment that starts before the next expected
// byte is compared with the bytes delivered last, as far back as they are
// kept. The distance back is a 32-bit sequence difference; it is taken as
// it is on every platform, also where an int has 32 bits, for every
// distance up to the largest an old segment can have.
func TestOldSegmentDistances(t *testing.T) {
	const next = 110 // after ten bytes from 100
	stream := []byte("0123456789")
	old := func(dist uint32, n int) []byte { // the n bytes the stream has (or would have) dist before next
		b := make([]byte, n)
		for i := range b {
			if p := int64(len(stream)) - int64(dist) + int64(i); p >= 0 && p < int64(len(stream)) {
				b[i] = stream[p]
			}
		}
		return b
	}
	cases := []struct {
		name                               string
		dist                               uint32
		payload                            []byte
		retransmits, keepalives, conflicts uint64
		held                               bool
	}{
		{"one byte back: a keepalive probe", 1, old(1, 1), 0, 1, 0, false},
		{"two bytes back", 2, old(2, 2), 1, 0, 0, false},
		{"two bytes back, other bytes", 2, []byte("xy"), 1, 0, 1, false},
		{"the whole tail", 10, old(10, 10), 1, 0, 0, false},
		{"the whole tail, last byte differs", 10, append(old(10, 9), 'x'), 1, 0, 1, false},
		{"one byte before the tail", 11, old(11, 11), 1, 0, 0, false},
		{"one byte before the tail, that byte differs", 11, append([]byte{'x'}, old(10, 10)...), 1, 0, 0, false},
		{"ends where the tail starts", 18, old(18, 8), 1, 0, 0, false},
		{"ends one byte into the tail", 17, append(old(17, 7), 'x'), 1, 0, 1, false},
		{"2^31-1 back", 1<<31 - 1, old(1<<31-1, 8), 1, 0, 0, false},
		{"2^31 back", 1 << 31, old(1<<31, 8), 1, 0, 0, false},
		{"2^31+7 back: the furthest an old segment of 8 bytes starts", 1<<31 + 7, old(1<<31+7, 8), 1, 0, 0, false},
		{"2^31+8 back: a segment ahead", 1<<31 + 8, old(1<<31+8, 8), 0, 0, 0, true},
		{"2^32-1 back: one byte ahead", 1<<32 - 1, old(1<<32-1, 8), 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &counter{}
			tr := NewTracker(Limits{TailKeep: 10}, h)
			segment(tr, clAddr, svAddr, 100, 0, link.ACK, stream)
			c := segment(tr, clAddr, svAddr, next-tc.dist, 0, link.ACK, tc.payload)
			if got := len(c.dirs[0].pend) == 1; got != tc.held {
				t.Errorf("held %v, want %v", got, tc.held)
			}
			if c.Stats.Retransmits != tc.retransmits || c.Stats.Keepalives != tc.keepalives || c.Stats.Conflicts != tc.conflicts {
				t.Errorf("retransmits %d, keepalives %d, conflicts %d; want %d, %d, %d", c.Stats.Retransmits, c.Stats.Keepalives,
					c.Stats.Conflicts, tc.retransmits, tc.keepalives, tc.conflicts)
			}
			if h.data != len(stream) || h.gaps != 0 {
				t.Errorf("%d bytes delivered, %d gaps", h.data, h.gaps)
			}
		})
	}
}

// TestAckedAhead: the peer's acknowledgement says how far a direction got;
// AckedAhead reports the bytes of it the capture has not delivered.
func TestAckedAhead(t *testing.T) {
	h := &counter{}
	tr := NewTracker(Limits{}, h)
	c := segment(tr, clAddr, svAddr, 100, 0, link.SYN, nil)
	if c.AckedAhead(0) || c.AckedAhead(1) {
		t.Error("ahead before any acknowledgement")
	}
	segment(tr, svAddr, clAddr, 500, 101, link.SYN|link.ACK, nil)
	segment(tr, clAddr, svAddr, 101, 501, link.ACK, []byte("abcd"))
	segment(tr, svAddr, clAddr, 501, 105, link.ACK, []byte("xy")) // acknowledges what was delivered
	if c.AckedAhead(0) || c.AckedAhead(1) {
		t.Error("ahead although every acknowledged byte was delivered")
	}
	segment(tr, svAddr, clAddr, 503, 109, link.ACK, []byte("z")) // four bytes the capture does not hold
	if !c.AckedAhead(0) || c.AckedAhead(1) {
		t.Errorf("client direction ahead %v, server direction ahead %v; want true, false", c.AckedAhead(0), c.AckedAhead(1))
	}
	segment(tr, clAddr, svAddr, 109, 504, link.ACK, []byte("ij")) // the bytes after the hole: it is declared a gap
	if c.AckedAhead(0) || h.gaps != 1 || h.gapBytes != 4 {
		t.Errorf("ahead %v after %d gaps of %d bytes in all; want false, one gap of 4 bytes", c.AckedAhead(0), h.gaps, h.gapBytes)
	}
	// A FIN takes a sequence number: its acknowledgement is not ahead.
	segment(tr, clAddr, svAddr, 111, 504, link.FIN|link.ACK, nil)
	segment(tr, svAddr, clAddr, 504, 112, link.ACK, nil)
	if c.AckedAhead(0) {
		t.Error("ahead after the acknowledgement of the FIN")
	}
	// A direction that never started, and one nobody acknowledged.
	m := segment(tr, netip.MustParseAddrPort("10.0.0.3:1"), svAddr, 7, 0, 0, []byte("a"))
	if m.AckedAhead(0) || m.AckedAhead(1) {
		t.Error("ahead without an acknowledgement")
	}
}

// holding feeds n one-byte segments to connection i, two sequence numbers
// apart from seq on, so that each is held behind a hole of its own.
func holding(tr *Tracker, i int, seq uint32, n int) {
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), 40000)
	for j := range n {
		segment(tr, src, svAddr, seq+uint32(2*j), 0, link.ACK, []byte{'h'})
	}
}

// TestBudgetVictim: when the total budget is reached, the connection that
// holds the most gives up its first hole; of connections that hold the
// same, the one seen last.
func TestBudgetVictim(t *testing.T) {
	const cost = 1 + heldOverhead
	var gaps []string
	h := &gapRecorder{gaps: &gaps}
	tr := NewTracker(Limits{BufferTotal: 12 * cost}, h)
	for i := range 4 {
		holding(tr, i, 100, 1) // delivered: the stream of each starts at 100
	}
	holding(tr, 0, 1000, 3)
	holding(tr, 1, 1000, 4)
	holding(tr, 2, 1000, 4)
	holding(tr, 3, 1000, 1) // 12 held: the budget is full
	holding(tr, 3, 1002, 1) // connections 2 and 3 hold four each: 3 was seen last
	holding(tr, 0, 1006, 1) // now connection 2 alone holds four
	holding(tr, 1, 1008, 1) // and now connection 1
	want := "[3 2 1]"
	if got := fmt.Sprint(gaps); got != want || tr.Stats.BudgetGaps != 3 {
		t.Errorf("connections that gave up a hole: %s, want %s; %d budget gaps", got, want, tr.Stats.BudgetGaps)
	}
	checkTracker(t, tr)
}

type gapRecorder struct {
	counter
	gaps *[]string
}

func (g *gapRecorder) Gap(c *Conn, _ int, _ uint64, _ int64, kind GapKind) {
	if kind == GapBudget {
		*g.gaps = append(*g.gaps, fmt.Sprint(c.ID))
	}
}

// budgetWork tracks conns connections, fills the total budget with held
// segments of 32 of them, holds extra more, and returns the comparisons the
// tracker made to choose which connection gives up a hole each time, and the
// holes given up.
func budgetWork(t *testing.T, conns, extra int) (work, gaps uint64) {
	t.Helper()
	const (
		cost    = 1 + heldOverhead
		holders = 32
		each    = 16
	)
	tr := NewTracker(Limits{MaxConns: conns, BufferPerDir: 1 << 20, BufferTotal: holders * each * cost}, &counter{})
	for i := range conns {
		holding(tr, i, 100, 1)
	}
	for i := range holders {
		holding(tr, i, 1000, each)
	}
	if tr.pendAll != tr.L.BufferTotal || tr.Stats.BudgetGaps != 0 || len(tr.conns) != conns {
		t.Fatalf("setup: %d bytes held of %d, %d budget gaps, %d connections", tr.pendAll, tr.L.BufferTotal, tr.Stats.BudgetGaps, len(tr.conns))
	}
	start := tr.work
	for j := range extra {
		holding(tr, j%holders, uint32(2000+2*j), 1)
	}
	checkTracker(t, tr)
	return tr.work - start, tr.Stats.BudgetGaps
}

// TestBudgetWork is the work budget of the total buffer limit
// (Limits.BufferTotal): with the budget full, every further held segment
// makes one connection give up a hole, and choosing it costs a number of
// steps that depends on the connections that hold bytes, not on the
// connections tracked. The steps are counted, not timed.
func TestBudgetWork(t *testing.T) {
	const extra = 2000
	few, gapsFew := budgetWork(t, 1000, extra)
	many, gapsMany := budgetWork(t, 20000, extra)
	if gapsFew != extra || gapsMany != extra {
		t.Errorf("%d and %d holes given up for %d held segments past the budget", gapsFew, gapsMany, extra)
	}
	// One hold, one drain and one touch reorder the 32 holders per segment:
	// each at most twice the depth of their heap, and a step up.
	limit := uint64(extra * 3 * (2*bits.Len(32) + 1))
	if many > limit {
		t.Errorf("%d held segments past the budget took %d steps with 20000 connections tracked, more than %d", extra, many, limit)
	}
	if many != few {
		t.Errorf("%d steps with 20000 connections tracked, %d with 1000: the work depends on the connections tracked", many, few)
	}
}

// TestBufferBudgetHeap measures what the tracker holds out of order, as
// live heap, against the total budget: one-byte segments held behind holes
// of their own, on many connections, many times the budget.
func TestBufferBudgetHeap(t *testing.T) {
	const (
		budget = 1 << 20
		conns  = 256
	)
	before := liveHeap()
	tr := NewTracker(Limits{MaxConns: conns, BufferPerDir: budget, BufferTotal: budget}, &counter{})
	for i := range conns {
		holding(tr, i, 100, 1)
	}
	base := liveHeap() - before // the connections themselves
	for i := range conns {
		holding(tr, i, 1000, 400) // 102,400 segments: more than twelve times the budget
	}
	checkTracker(t, tr)
	held := liveHeap() - before - base
	if tr.pendAll > budget || tr.Stats.BudgetGaps == 0 {
		t.Errorf("%d bytes charged with a budget of %d, %d budget gaps", tr.pendAll, budget, tr.Stats.BudgetGaps)
	}
	// A held segment is charged 129 bytes and takes about 120 of heap for
	// its entry and its byte; the lists grow by doubling.
	if limit := int64(3 * budget); held > limit {
		t.Errorf("%d bytes live for held segments with a budget of %d: more than %d", held, budget, limit)
	}
	runtime.KeepAlive(tr)
}

func liveHeap() int64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// checkTracker fails when the tracker's accounting does not add up: the
// bytes charged are those of the segments held, within the limits; the held
// segments of a direction are in sequence order; and the connections that
// hold bytes are exactly the holders, in heap order.
func checkTracker(t *testing.T, tr *Tracker) {
	t.Helper()
	total, holders, listed := 0, 0, 0
	for c := tr.lru.next; c != &tr.lru; c = c.next {
		listed++
		if tr.conns[c.key] != c {
			t.Fatalf("connection %d is listed but not tracked", c.ID)
		}
		for d := range c.dirs {
			h := &c.dirs[d]
			sum := 0
			for i, p := range h.pend {
				sum += p.cost
				if p.cost != len(p.data)+heldOverhead || (i > 0 && seqLT(p.seq, h.pend[i-1].seq)) || !seqLT(h.next, p.seq) {
					t.Fatalf("connection %d direction %d: held segment %d at %d (next %d) costs %d for %d bytes", c.ID, d, i, p.seq, h.next, p.cost, len(p.data))
				}
			}
			if sum != h.pendLen || (len(h.pend) > 1 && h.pendLen > tr.L.BufferPerDir) {
				t.Fatalf("connection %d direction %d: %d bytes charged, %d held, limit %d", c.ID, d, h.pendLen, sum, tr.L.BufferPerDir)
			}
			total += sum
		}
		if c.held() > 0 {
			holders++
			if c.holder < 1 || c.holder > len(tr.holders) || tr.holders[c.holder-1] != c || c.Close != Live {
				t.Fatalf("connection %d holds %d bytes and is not a holder (index %d of %d, close %v)", c.ID, c.held(), c.holder, len(tr.holders), c.Close)
			}
		} else if c.holder != 0 {
			t.Fatalf("connection %d holds nothing and is a holder", c.ID)
		}
	}
	if total != tr.pendAll || holders != len(tr.holders) || listed != len(tr.conns) || len(tr.conns) > tr.L.MaxConns {
		t.Fatalf("%d bytes charged, %d held; %d holders, %d in the heap; %d connections listed, %d tracked, limit %d",
			tr.pendAll, total, holders, len(tr.holders), listed, len(tr.conns), tr.L.MaxConns)
	}
	if tr.pendAll > tr.L.BufferTotal {
		t.Fatalf("%d bytes held with a total budget of %d", tr.pendAll, tr.L.BufferTotal)
	}
	for i := 1; i < len(tr.holders); i++ {
		if tr.holders[i].outranks(tr.holders[(i-1)/2]) {
			t.Fatalf("holder %d outranks its parent", i)
		}
	}
}

// streams is a Handler that checks the order of what it is given. The
// fuzz target makes every payload byte the low byte of its own sequence
// number, so the bytes of a direction count up by one, across gaps too.
type streams struct {
	t      *testing.T
	open   map[uint32]bool
	closed map[uint32]bool
	pos    map[[2]uint32]uint64
	next   map[[2]uint32]byte
	seen   map[[2]uint32]bool
}

func (s *streams) Open(c *Conn) {
	if s.open[c.ID] || c.Open == 0 {
		s.t.Fatalf("connection %d opened twice or without a kind (%v)", c.ID, c.Open)
	}
	s.open[c.ID] = true
}

func (s *streams) at(c *Conn, d int, pos uint64) [2]uint32 {
	k := [2]uint32{c.ID, uint32(d)}
	if !s.open[c.ID] || s.closed[c.ID] {
		s.t.Fatalf("connection %d: an event before Open or after Close", c.ID)
	}
	if s.pos[k] != pos {
		s.t.Fatalf("connection %d direction %d: position %d, want %d", c.ID, d, pos, s.pos[k])
	}
	return k
}

func (s *streams) Data(c *Conn, d int, pos uint64, b []byte, _ Chunk) {
	k := s.at(c, d, pos)
	if len(b) == 0 {
		s.t.Fatalf("connection %d: an empty delivery", c.ID)
	}
	if !s.seen[k] {
		s.seen[k], s.next[k] = true, b[0]
	}
	for i, x := range b {
		if x != s.next[k]+byte(i) {
			s.t.Fatalf("connection %d direction %d: byte %d at position %d, want %d: delivered twice or out of order", c.ID, d, x, pos+uint64(i), s.next[k]+byte(i))
		}
	}
	s.next[k] += byte(len(b))
	s.pos[k] += uint64(len(b))
}

func (s *streams) Repeat(c *Conn, d int, pos, end uint64) {
	if k := [2]uint32{c.ID, uint32(d)}; pos >= end || end > s.pos[k] {
		s.t.Fatalf("connection %d direction %d: bytes %d to %d seen again, %d delivered", c.ID, d, pos, end, s.pos[k])
	}
}

func (s *streams) Gap(c *Conn, d int, pos uint64, n int64, kind GapKind) {
	k := s.at(c, d, pos)
	if n <= 0 || kind < GapLoss || kind > GapBudget {
		s.t.Fatalf("connection %d: a gap of %d bytes, kind %v", c.ID, n, kind)
	}
	s.next[k] += byte(n)
	s.pos[k] += uint64(n)
}

func (s *streams) Close(c *Conn) {
	if !s.open[c.ID] || s.closed[c.ID] || c.Close == Live {
		s.t.Fatalf("connection %d closed twice, before Open or without a kind", c.ID)
	}
	s.closed[c.ID] = true
}

// FuzzSegments feeds a sequence of TCP segments of a few connections to
// the tracker, with limits small enough for every one of them to be
// reached: more connections than are tracked, out-of-order bytes past the
// limit of a direction and past the total budget, SYN, FIN and RST at any
// point, sequence numbers around the wrap. Each segment is four bytes of
// input. After every segment the accounting adds up and is within the
// limits, and every direction got its bytes once, in order, with every hole
// reported at its size. At the end nothing is held and every connection was
// closed once.
func FuzzSegments(f *testing.F) {
	f.Add([]byte{0x00, 0, 4, 0, 0x04, 0, 4, 4, 0x00, 4, 4, 4})                            // a request and its answer
	f.Add([]byte{0x00, 0, 4, 0, 0x00, 12, 4, 0, 0x00, 8, 4, 0, 0x00, 4, 4, 0})            // out of order, then filled
	f.Add([]byte{0x08, 0, 0, 0, 0x0c, 0, 0, 1, 0x00, 1, 8, 1, 0x10, 9, 0, 1})             // SYN, SYN+ACK, data, FIN
	f.Add([]byte{0x00, 0, 8, 0, 0x00, 2, 8, 0, 0x00, 250, 8, 0, 0x04, 0, 1, 200})         // overlap, a far segment, an acknowledgement ahead
	f.Add([]byte{0x00, 0, 1, 0, 0x01, 0, 1, 0, 0x02, 0, 1, 0, 0x03, 0, 1, 0, 0, 9, 1, 0}) // more connections than are tracked
	f.Add([]byte{0x00, 0, 31, 0, 0x00, 40, 31, 0, 0x00, 80, 31, 0, 0x00, 120, 31, 0, 0x00, 160, 31, 0, 0x00, 200, 31, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		h := &streams{t: t, open: map[uint32]bool{}, closed: map[uint32]bool{}, pos: map[[2]uint32]uint64{}, next: map[[2]uint32]byte{},
			seen: map[[2]uint32]bool{}}
		tr := NewTracker(Limits{MaxConns: 3, BufferPerDir: 4 * (16 + heldOverhead), BufferTotal: 6 * (16 + heldOverhead), TailKeep: 8, EpochWindow: 1 << 12}, h)
		base := [2]uint32{0xFFFFFF80, 0x7FFFFF80} // the sequence numbers of the two directions, near the wraps
		for i := 0; i+4 <= len(in) && i < 4*1024; i += 4 {
			client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 40000+uint16(in[i]&3))
			dir := int(in[i] >> 2 & 1)
			var flags uint8 = link.ACK
			if in[i]&0x08 != 0 {
				flags |= link.SYN
				if dir == 0 {
					flags &^= link.ACK
				}
			}
			if in[i]&0x10 != 0 {
				flags |= link.FIN
			}
			if in[i]&0xe0 == 0xe0 {
				flags |= link.RST
			}
			seq := base[dir] + uint32(in[i+1])
			if in[i]&0xc0 == 0x40 {
				seq += 1 << 13 // past the window of an epoch
			}
			payload := make([]byte, in[i+2]&0x1f)
			first := seq
			if flags&link.SYN != 0 {
				first++ // the SYN takes a sequence number
			}
			for j := range payload {
				payload[j] = byte(first + uint32(j))
			}
			s := link.Segment{Src: client, Dst: svAddr, Seq: seq, Ack: base[1-dir] + uint32(in[i+3]), Flags: flags, Payload: payload,
				Missing: uint32(in[i+2] >> 5 & 3)}
			if dir == 1 {
				s.Src, s.Dst = s.Dst, s.Src
			}
			tr.Packet(&pcapio.Packet{Frame: uint64(i/4 + 1), HasTime: true, TimeNS: int64(i + 1)}, &s)
			checkTracker(t, tr)
		}
		tr.Finish()
		checkTracker(t, tr)
		if tr.pendAll != 0 || len(tr.holders) != 0 {
			t.Fatalf("at the end %d bytes are held by %d connections", tr.pendAll, len(tr.holders))
		}
		if len(h.open) != len(h.closed) || uint64(len(h.open)) != tr.Stats.Conns {
			t.Fatalf("%d connections opened, %d closed, %d counted", len(h.open), len(h.closed), tr.Stats.Conns)
		}
		if tr.Stats.Conflicts != 0 {
			t.Fatalf("%d conflicting overlaps, and every copy of a byte is the same", tr.Stats.Conflicts)
		}
	})
}
