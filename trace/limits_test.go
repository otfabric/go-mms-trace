// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/netip"
	"runtime"
	"testing"

	"github.com/otfabric/go-cotp"

	"github.com/otfabric/go-mms-trace/internal/flow"
	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() int64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

func gzipped(t testing.TB, b []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// requests builds a capture of one association with n Read requests, 24
// to a TCP segment: the capture that makes the most of a result for its
// size, since every request becomes a transaction with its decoded PDU.
func requests(t testing.TB, e exchange, n int) []byte {
	t.Helper()
	c := newCapture(t)
	c.handshake()
	c.units(e.setup, false)
	one := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: e.req}))
	seg := bytes.Repeat(one, 24)
	for i := 0; i < n; i += 24 {
		c.tcp(0, 0x18, seg)
	}
	return c.bytes(t)
}

// TestMaxBytes is the allocation budget of Options.MaxBytes: of a gzip
// input that unpacks to many times the limit, the analysis reads the limit
// and no more, returns what it found with ErrLimit, and the result it
// holds is bounded by the limit, not by the input. The same holds for a
// plain input. An input within the limit is read whole.
func TestMaxBytes(t *testing.T) {
	const limit = 1 << 20
	e := readExchange(t)
	plain := requests(t, e, 150_000)
	gz := gzipped(t, plain)
	if len(plain) < 6*limit || len(gz) > limit/4 {
		t.Fatalf("the capture has %d bytes, %d as gzip", len(plain), len(gz))
	}
	for name, in := range map[string][]byte{"plain": plain, "gzip": gz} {
		before := liveHeap()
		res, err := Analyze(context.Background(), bytes.NewReader(in), Options{MaxBytes: limit})
		held := liveHeap() - before
		if !errors.Is(err, ErrLimit) || errors.Is(err, ErrCorrupt) || res == nil {
			t.Fatalf("%s: err %v, result %v; want a result and ErrLimit", name, err, res != nil)
		}
		f := res.File
		if f.UncompressedBytes > limit || f.UncompressedBytes < limit-2000 || f.Gzip != (name == "gzip") || f.TruncatedTail {
			t.Errorf("%s: %d bytes of capture read with a limit of %d (gzip %v, truncated %v)", name, f.UncompressedBytes, limit, f.Gzip, f.TruncatedTail)
		}
		// The input is read in pieces of 256 KiB.
		if maxIn := int64(min(len(in), limit+256<<10)); f.InputBytes > maxIn || f.InputBytes <= 0 {
			t.Errorf("%s: %d bytes of input read, at most %d expected", name, f.InputBytes, maxIn)
		}
		if n := len(res.Transactions); n < 10_000 || n > 30_000 || res.Associations[0].Transactions != n {
			t.Errorf("%s: %d transactions", name, n)
		}
		// SECURITY.md: a result takes up to about 30 times the capture read
		// (8.4 times for this one).
		if budget := int64(30 * limit); held > budget {
			t.Errorf("%s: the result holds %d bytes for a limit of %d: more than %d", name, held, limit, budget)
		}
		runtime.KeepAlive(res)
	}
	runtime.KeepAlive(plain) // every measurement has both inputs in it
	runtime.KeepAlive(gz)
	// At the size of the capture and above it, nothing is refused.
	small := requests(t, e, 48)
	for _, tc := range []struct {
		max   int64
		limit bool
	}{{int64(len(small)) - 1, true}, {int64(len(small)), false}, {int64(len(small)) + 1, false}, {0, false}, {-1, false}, {math.MaxInt64, false}} {
		for name, in := range map[string][]byte{"plain": small, "gzip": gzipped(t, small)} {
			res, err := Analyze(context.Background(), bytes.NewReader(in), Options{MaxBytes: tc.max})
			if errors.Is(err, ErrLimit) != tc.limit || res == nil || (!tc.limit && (err != nil || len(res.Transactions) != 48 || res.File.UncompressedBytes != int64(len(small)))) {
				t.Errorf("%s, MaxBytes %d of %d: err %v", name, tc.max, len(small), err)
			}
		}
	}
}

// TestInterfaceAndSectionLimits: Options.MaxInterfaces and
// Options.MaxSections through Analyze, at the limit and around it.
func TestInterfaceAndSectionLimits(t *testing.T) {
	interfaces := func(n int) []byte {
		var buf bytes.Buffer
		w, err := pcapio.NewNgWriter(&buf, pcapio.Section{}, nil)
		for i := range n {
			err = errors.Join(err, w.AddInterface(pcapio.Interface{LinkType: 1}), w.WritePacket(uint32(i), 1e9, 0, make([]byte, 14)))
		}
		if err = errors.Join(err, w.Flush()); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	sections := func(n int) []byte {
		var buf bytes.Buffer
		w, err := pcapio.NewNgWriter(&buf, pcapio.Section{}, []pcapio.Interface{{LinkType: 1}})
		for i := range n {
			if i > 0 {
				err = errors.Join(err, w.NewSection(pcapio.Section{}, []pcapio.Interface{{LinkType: 1}}))
			}
			err = errors.Join(err, w.WritePacket(0, 1e9, 0, make([]byte, 14)))
		}
		if err = errors.Join(err, w.Flush()); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	for _, tc := range []struct{ limit, have, want int }{{3, 2, 2}, {3, 3, 3}, {3, 4, 3}, {3, 30, 3}, {0, 5, 5},
		{0, DefaultMaxInterfaces, DefaultMaxInterfaces}, {0, DefaultMaxInterfaces + 1, DefaultMaxInterfaces}} {
		res, err := Analyze(context.Background(), bytes.NewReader(interfaces(tc.have)), Options{MaxInterfaces: tc.limit})
		if err != nil {
			t.Fatal(err)
		}
		if f := res.File; f.Interfaces != tc.want || len(f.Links) != tc.want || f.Packets != uint64(tc.want) || f.SkippedBlocks != uint64(2*(tc.have-tc.want)) {
			t.Errorf("MaxInterfaces %d, %d in the file: %d interfaces, %d packets, %d blocks skipped; want %d", tc.limit, tc.have, f.Interfaces, f.Packets, f.SkippedBlocks, tc.want)
		}
	}
	for _, tc := range []struct{ limit, have, want int }{{3, 2, 2}, {3, 3, 3}, {3, 4, 3}, {3, 30, 3}, {0, 5, 5},
		{0, DefaultMaxSections, DefaultMaxSections}, {0, DefaultMaxSections + 1, DefaultMaxSections}} {
		res, err := Analyze(context.Background(), bytes.NewReader(sections(tc.have)), Options{MaxSections: tc.limit})
		if over := tc.have > tc.want; errors.Is(err, ErrLimit) != over || (err != nil && !over) || res == nil || res.File.Packets != uint64(tc.want) {
			t.Errorf("MaxSections %d, %d in the file: err %v; want %d packets, ErrLimit %v", tc.limit, tc.have, err, tc.want, over)
		}
	}
}

// twoParts returns a TPKT frame with the first half of an InformationReport
// in a DT TPDU that is not the last of its TSDU, and the frame with the
// rest.
func twoParts(t testing.TB, report []byte) (first, last []byte) {
	t.Helper()
	h := len(report) / 2
	return tpkt(marshal(t, &cotp.DT{UserData: report[:h]})), tpkt(marshal(t, &cotp.DT{EOT: true, UserData: report[h:]}))
}

// TestAssemblyBudget: Options.MaxAssembly bounds what all connections
// together hold of incomplete TSDUs and TPKT frames. Beyond it the
// direction that has waited longest gives up what it holds: the first
// connections of the capture lose their PDU, the last ones keep it, and
// each loss is counted.
func TestAssemblyBudget(t *testing.T) {
	const conns = 40
	report := informationReport(t)
	first, last := twoParts(t, report)
	whole := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: report}))
	build := func(a, b []byte) []byte { // every connection sends a, then every connection sends b
		c := newCapture(t)
		for _, part := range [][]byte{a, b} {
			for i := range conns {
				c.port = uint16(40000 + i)
				c.seq = [2]uint32{1, 1}
				if bytes.Equal(part, b) {
					c.seq[1] += uint32(len(a))
				}
				c.tcp(1, 0x18, part)
			}
		}
		return c.bytes(t)
	}
	cases := []struct {
		name   string
		file   []byte
		budget int
		kept   func(n int) bool   // how many connections keep their report
		count  func(*Result, int) // the counters, given the number that kept it
	}{
		{"incomplete TSDUs, the default budget", build(first, last), 0, func(n int) bool { return n == conns },
			func(res *Result, n int) {
				if c := res.Counters; c.TSDUErrors != 0 || c.TPKTResync != 0 {
					t.Errorf("counters %+v", c)
				}
			}},
		{"incomplete TSDUs, a budget for a part of them", build(first, last), 12 * len(report) / 2, func(n int) bool { return n >= 4 && n <= 12 },
			func(res *Result, n int) {
				if c := res.Counters; c.TSDUErrors != uint64(conns-n) || c.TPKTResync != 0 {
					t.Errorf("counters %+v, want %d TSDU errors", c, conns-n)
				}
			}},
		{"incomplete TSDUs, a budget below one of them", build(first, last), 8, func(n int) bool { return n == 0 },
			func(res *Result, n int) {
				if c := res.Counters; c.TSDUErrors != conns {
					t.Errorf("counters %+v", c)
				}
			}},
		{"incomplete frames, the default budget", build(whole[:40], whole[40:]), 0, func(n int) bool { return n == conns },
			func(res *Result, n int) {
				if c := res.Counters; c.TSDUErrors != 0 || c.TPKTResync != 0 {
					t.Errorf("counters %+v", c)
				}
			}},
		{"incomplete frames, a budget for a part of them", build(whole[:40], whole[40:]), 12 * 40, func(n int) bool { return n >= 4 && n <= 12 },
			func(res *Result, n int) {
				// The frame given up and its rest are bytes that are no
				// frame; the last few of a connection are not looked at
				// before more arrive.
				lo, hi := uint64((conns-n)*(len(whole)-3)), uint64((conns-n)*len(whole))
				if c := res.Counters; c.TPKTResync < lo || c.TPKTResync > hi || c.TSDUErrors != 0 || c.COTPErrors != 0 {
					t.Errorf("counters %+v, want %d to %d bytes skipped", c, lo, hi)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Analyze(context.Background(), bytes.NewReader(tc.file), Options{MaxAssembly: tc.budget})
			if err != nil {
				t.Fatal(err)
			}
			n := len(res.Reports)
			if !tc.kept(n) {
				t.Fatalf("%d of %d connections kept their report", n, conns)
			}
			tc.count(res, n)
			// The connections that kept it are the ones fed last.
			for i, r := range res.Reports {
				assoc := res.Associations[r.Association-1]
				if want := uint16(40000 + conns - n + i); assoc.Client.Port() != want {
					t.Errorf("report %d is of the connection from port %d, want %d", i, assoc.Client.Port(), want)
				}
			}
		})
	}
}

// TestAssemblyBudgetHeap is the allocation budget of Options.MaxAssembly:
// directions that each hold an incomplete TSDU or frame, many times the
// budget in all, cost the analysis the budget and what a connection takes
// by itself.
func TestAssemblyBudgetHeap(t *testing.T) {
	const (
		budget = 1 << 20
		conns  = 2000
		part   = 16 << 10
	)
	frame := tpkt(marshal(t, &cotp.DT{UserData: make([]byte, part)})) // a part of a TSDU, not its last
	for name, feed := range map[string][]byte{"TSDUs": frame, "frames": frame[:len(frame)-1]} {
		before := liveHeap()
		a := newAnalyzer(Options{Ports: DefaultPorts, MaxAssembly: budget})
		cs := make([]*flow.Conn, conns)
		for i := range cs {
			cs[i] = &flow.Conn{SYNFrom: 0, SYNACKFrom: 1, Endpoints: [2]netip.AddrPort{
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000), netip.MustParseAddrPort("10.9.9.9:102")}}
			a.Open(cs[i])
		}
		base := liveHeap() - before
		for round := range 3 {
			for i, c := range cs {
				a.Data(c, 0, uint64(round*len(feed)), feed, flow.Chunk{Frame: uint64(i + 1)})
				if a.heldLen > budget {
					t.Fatalf("%s: %d bytes charged with a budget of %d", name, a.heldLen, budget)
				}
			}
		}
		held := liveHeap() - before - base
		// What is charged is what is allocated; a buffer that grows is
		// allocated twice for a moment, and the last direction fed may hold
		// a buffer the size of what it was fed more than the budget.
		if limit := int64(budget + 4*part + conns*512); held > limit { // and an association per connection
			t.Errorf("%s: %d bytes live for %d bytes fed with a budget of %d: more than %d", name, held, 3*conns*len(feed), budget, limit)
		}
		for _, c := range cs {
			a.Close(c)
		}
		if a.heldLen != 0 || a.held.next != &a.held || a.held.prev != &a.held {
			t.Errorf("%s: %d bytes charged after every connection closed", name, a.heldLen)
		}
		runtime.KeepAlive(cs)
	}
}

// heapAtEnd is a reader that measures the live heap when its input ends:
// what an analysis holds at the end of its pass, before it returns.
type heapAtEnd struct {
	r    io.Reader
	heap int64
}

func (h *heapAtEnd) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if err == io.EOF {
		h.heap = liveHeap()
	}
	return n, err
}

// TestConnectionLimitHeap is the allocation budget of the connection limit,
// through Analyze at its default: of a capture with more connections than
// are tracked (each one segment on an MMS port), the analysis holds the
// 100,000 it tracks and no more, at about 1 KiB each.
func TestConnectionLimitHeap(t *testing.T) {
	const conns = 250_000
	file := func() []byte {
		c := newCapture(t)
		c.tcp(0, 0x18, []byte{0})
		one := c.bytes(t)[24+16:] // the packet of the one record
		pkts := make([]packetRecord, conns)
		for i := range pkts {
			p := bytes.Clone(one)
			p[27], p[28], p[29] = byte(i>>16), byte(i>>8), byte(i) // the client's address
			pkts[i] = packetRecord{ns: int64(i+1) * 1000, origLen: uint32(len(p)), data: p}
		}
		return pcapWithout(1, pkts, -1)
	}()
	before := liveHeap()
	r := &heapAtEnd{r: bytes.NewReader(file)}
	res, err := Analyze(context.Background(), r, Options{})
	if err != nil || res.File.Packets != conns || len(res.Associations) != 0 {
		t.Fatalf("err %v, %d packets, %d associations", err, res.File.Packets, len(res.Associations))
	}
	// Measured: 1.1 KiB for each tracked connection. All 250,000 would be
	// 260 MiB.
	if held, budget := r.heap-before, int64(flow.DefaultLimits.MaxConns*1536); held > budget || held < budget/8 {
		t.Errorf("%d bytes live at the end of %d connections: the budget of the %d tracked is %d", held, conns, flow.DefaultLimits.MaxConns, budget)
	}
	runtime.KeepAlive(file)
}

// TestTSDULimitHeap is the allocation budget of the TSDU limit, through
// Analyze at its default (MaxTSDU): a TSDU that grows past the limit is
// dropped when it passes it, not when it ends, so the analysis does not
// hold the parts of a TSDU that will not be decoded. One TSDU of 17 MiB in
// frames of 60 KiB: when the input ends, with the last frames still to
// come, nothing of it is held.
func TestTSDULimitHeap(t *testing.T) {
	const part = 60 << 10
	file := func() []byte {
		c := newCapture(t)
		c.handshake()
		data := make([]byte, part)
		for sent := 0; sent < MaxTSDU+1<<20; sent += part {
			c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{UserData: data})))
		}
		c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: data})))
		return bytes.Clone(c.bytes(t))
	}()
	before := liveHeap()
	r := &heapAtEnd{r: bytes.NewReader(file)}
	res, err := Analyze(context.Background(), r, Options{})
	if err != nil || res.Counters.TSDUErrors != 1 || res.Counters.COTPErrors != 0 || res.Counters.TPKTResync != 0 || len(res.Associations) != 1 {
		t.Fatalf("err %v, counters %+v, %d associations", err, res.Counters, len(res.Associations))
	}
	// The reader's buffers and the frames it has not handed on yet.
	if held, budget := r.heap-before, int64(2<<20); held > budget {
		t.Errorf("%d bytes live at the end of a TSDU of %d bytes, more than %d", held, MaxTSDU+1<<20, budget)
	}
	runtime.KeepAlive(file)
}

// TestGooseKeepsNoScratch: what a GOOSE stream needs during the pass to
// compare its messages (every pair of numbers seen, a count per second) is
// not held by the result.
func TestGooseKeepsNoScratch(t *testing.T) {
	const n = 20_000
	file := func() []byte { // in a function of its own: the writer and its buffers are gone when it returns
		c := newCapture(t)
		for i := range n {
			c.goose(t, uint32(1+i/4), uint32(i%4))
		}
		return bytes.Clone(c.bytes(t))
	}()
	before := liveHeap()
	res, err := Analyze(context.Background(), bytes.NewReader(file), Options{})
	held := liveHeap() - before
	if err != nil || len(res.GOOSE) != 1 || res.GOOSE[0].Messages != n || res.GOOSE[0].Changes != n/4-1 || len(res.GOOSE[0].Issues) != 0 || res.GOOSE[0].MaxPerSecond != 1000 {
		t.Fatalf("err %v, GOOSE %+v", err, res.GOOSE)
	}
	if held > 64<<10 {
		t.Errorf("the result of %d GOOSE messages of one stream holds %d bytes", n, held)
	}
	runtime.KeepAlive(file) // both measurements have the capture in them
	runtime.KeepAlive(res)
}

// fragment writes an IPv4 fragment of a datagram from the server to the
// client: bytes of the TCP segment at offset off.
func (c *capture) fragment(id uint16, off int, more bool, payload []byte) {
	b := append([]byte{}, clientMAC...)
	b = append(b, serverMAC...)
	b = append(b, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(ip[4:], id)
	fo := uint16(off / 8)
	if more {
		fo |= 0x2000
	}
	binary.BigEndian.PutUint16(ip[6:], fo)
	ip[8], ip[9] = 64, 6
	copy(ip[12:], serverIP)
	copy(ip[16:], clientIP)
	c.packet(append(append(b, ip...), payload...))
}

// TestAnalyzeFragments: IP fragments through Analyze. A last fragment that
// ends before the fragments held is counted as fragment_bad, and the
// analysis goes on: the next datagram, in fragments too, is reassembled and
// its PDU found.
func TestAnalyzeFragments(t *testing.T) {
	report := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: informationReport(t)}))
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 102)
	binary.BigEndian.PutUint16(tcp[2:], 40000)
	binary.BigEndian.PutUint32(tcp[4:], 1)
	tcp[12], tcp[13] = 5<<4, 0x18
	seg := append(tcp, report...)
	if len(seg) < 48 {
		t.Fatalf("a segment of %d bytes", len(seg))
	}
	c := newCapture(t)
	c.fragment(7, 0, true, seg[:16])
	c.fragment(7, 16, true, seg[16:32])
	c.fragment(7, 8, false, seg[8:9]) // ends before the 32 bytes held
	c.fragment(8, 16, true, seg[16:32])
	c.fragment(8, 32, false, seg[32:])
	c.fragment(8, 0, true, seg[:16])
	res := analyze(t, c.bytes(t))
	if n := res.Counters.Unsupported["fragment_bad"]; n != 1 || len(res.Counters.Unsupported) != 1 {
		t.Errorf("unsupported %v, want one fragment_bad", res.Counters.Unsupported)
	}
	if len(res.Reports) != 1 || len(res.Associations) != 1 || res.Reports[0].Frame != 6 || res.File.Packets != 6 {
		t.Errorf("%d reports, %d associations, %d packets", len(res.Reports), len(res.Associations), res.File.Packets)
	}
}
