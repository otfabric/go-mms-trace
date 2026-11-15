// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/otfabric/go-cotp"

	"github.com/otfabric/go-mms-trace/internal/flow"
)

// checkResult fails when a result does not add up: every transaction and
// report belongs to an association and is counted there, every status is
// one of the constants, and what the status says of the PDUs holds.
func checkResult(t *testing.T, res *Result) {
	t.Helper()
	if res.Counters.Unsupported == nil || res.File.Links == nil || len(res.File.Links) != res.File.Interfaces {
		t.Fatalf("file %+v, counters %+v", res.File, res.Counters)
	}
	tx, reports, unanswered := make([]int, len(res.Associations)+1), make([]int, len(res.Associations)+1), make([]int, len(res.Associations)+1)
	for _, tr := range res.Transactions {
		if tr.Association < 1 || tr.Association > len(res.Associations) {
			t.Fatalf("a transaction of association %d of %d", tr.Association, len(res.Associations))
		}
		tx[tr.Association]++
		req, resp := tr.Request != nil, tr.Response != nil
		switch tr.Status {
		case StatusOK, StatusError, StatusReject, StatusUncertain:
			if !req || !resp {
				t.Fatalf("status %q without both PDUs", tr.Status)
			}
		case StatusUnanswered, StatusPending:
			if !req || resp {
				t.Fatalf("status %q with a response or without a request", tr.Status)
			}
			if tr.Status == StatusUnanswered {
				unanswered[tr.Association]++
			}
		case StatusOrphan:
			if req || !resp {
				t.Fatalf("status %q with a request or without a response", tr.Status)
			}
		default:
			t.Fatalf("status %q", tr.Status)
		}
	}
	for _, r := range res.Reports {
		if r.Association < 1 || r.Association > len(res.Associations) || r.PDU == nil {
			t.Fatalf("a report of association %d of %d", r.Association, len(res.Associations))
		}
		reports[r.Association]++
	}
	for i, as := range res.Associations {
		if as.ID != i+1 || as.Transactions != tx[as.ID] || as.Reports != reports[as.ID] || as.Unanswered != unanswered[as.ID] || as.Gaps < 0 {
			t.Fatalf("association %d: %+v; %d transactions, %d reports, %d unanswered in the result", i+1, as, tx[i+1], reports[i+1], unanswered[i+1])
		}
	}
	for _, g := range res.GOOSE {
		if g.Messages < 1 || g.Changes >= g.Messages || g.seen != nil || g.perSecond != nil || g.last != nil {
			t.Fatalf("GOOSE stream %+v", g)
		}
	}
}

// FuzzAnalyze: arbitrary bytes into Analyze. A result comes back exactly
// when the error is nil or wraps ErrCorrupt or ErrLimit, it adds up, and
// the analysis read no more of the capture than the limit it was given.
func FuzzAnalyze(f *testing.F) {
	for _, p := range []string{fixtureFile, damagedFile} {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
			f.Add(b[:len(b)/2])
			f.Add(gzipped(f, b))
		}
	}
	f.Add([]byte("not a capture"))
	f.Fuzz(func(t *testing.T, b []byte) {
		const limit = 1 << 20
		res, err := Analyze(context.Background(), bytes.NewReader(b), Options{MaxPacket: 1 << 16, MaxBytes: limit, MaxInterfaces: 4, MaxSections: 4, MaxAssembly: 4096})
		partial := errors.Is(err, ErrCorrupt) || errors.Is(err, ErrLimit)
		if (res != nil) != (err == nil || partial) || (err != nil && !partial && !errors.Is(err, ErrFormat)) {
			t.Fatalf("result %v with error %v", res != nil, err)
		}
		if res == nil {
			return
		}
		if res.File.UncompressedBytes > limit || res.File.Interfaces > 4 || res.File.InputBytes > int64(len(b)) {
			t.Fatalf("file %+v with a limit of %d bytes and 4 interfaces, an input of %d bytes", res.File, limit, len(b))
		}
		checkResult(t, res)
	})
}

// framerScript is the bytes one direction would send: InformationReports,
// each a TSDU in one frame or in two.
func framerScript(t testing.TB, report []byte, n int) (stream []byte, ends []int) {
	t.Helper()
	whole := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: report}))
	first, last := twoParts(t, report)
	for i := range n {
		if i%3 == 2 {
			stream = append(append(stream, first...), last...)
		} else {
			stream = append(stream, whole...)
		}
		ends = append(ends, len(stream))
	}
	return stream, ends
}

// fuzzReport is the report of the framer's fuzz target, recorded once: the
// target runs many times in a process.
var fuzzReport []byte

func recordedReport(t testing.TB) []byte {
	if fuzzReport == nil {
		fuzzReport = informationReport(t)
	}
	return fuzzReport
}

// FuzzFramer feeds the ISO stage of two connections what the TCP stage
// would deliver: for each direction the bytes of a script of PDUs in
// pieces of any size, with holes (bytes of the script that are skipped as
// a gap) and bytes of the input in between. Each step is three bytes of
// input.
//
// After every step what the directions hold is what is charged, within
// the assembly budget, and no direction holds more than a frame and a TSDU
// can have. A direction that got its script whole, without a hole and
// without other bytes, yields every PDU of it when the budget is large. At
// the end nothing is charged.
func FuzzFramer(f *testing.F) {
	f.Add([]byte{0, 200, 0, 0, 200, 0, 0, 200, 0, 4, 200, 0})            // one direction, in order
	f.Add([]byte{0, 7, 0, 1, 9, 0, 0, 30, 0, 1, 255, 0, 0, 255, 0})      // two directions in small pieces
	f.Add([]byte{0, 50, 0, 2, 20, 0, 0, 255, 0, 0, 255, 0})              // a hole
	f.Add([]byte{0, 10, 0, 3, 5, 3, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0}) // bytes that are no frame
	f.Add([]byte{8, 100, 0, 9, 100, 0, 12, 100, 0, 13, 100, 0, 4, 0, 0}) // a small budget, four directions
	f.Fuzz(func(t *testing.T, in []byte) {
		report := recordedReport(t)
		const pdus = 12
		stream, ends := framerScript(t, report, pdus)
		budget := DefaultMaxAssembly
		if len(in) > 0 && in[0]&8 != 0 {
			budget = 3 * len(report)
		}
		a := newAnalyzer(Options{Ports: DefaultPorts, MaxAssembly: budget})
		type dirState struct {
			sent  int    // bytes of the script delivered or skipped
			pos   uint64 // stream position
			clean bool   // only bytes of the script so far, and all of them
		}
		conns := [2]*flow.Conn{}
		dirs := [2][2]dirState{}
		for i := range conns {
			conns[i] = &flow.Conn{SYNFrom: 0, SYNACKFrom: 1, Endpoints: [2]netip.AddrPort{
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), uint16(40000+i)), netip.MustParseAddrPort("10.0.0.2:102")}}
			a.Open(conns[i])
			dirs[i] = [2]dirState{{clean: true}, {clean: true}}
		}
		check := func() {
			total, listed := 0, 0
			for d := a.held.next; d != &a.held; d = d.next {
				listed++
				if d.next.prev != d {
					t.Fatal("the list of holders is broken")
				}
			}
			holding := 0
			for _, c := range conns {
				cs := c.User.(*conn)
				for i := range cs.dirs {
					d := &cs.dirs[i]
					if d.charged != cap(d.buf)+cap(d.tsdu) || len(d.buf) > 65535 || len(d.tsdu) > maxTSDU {
						t.Fatalf("a direction holds %d and %d bytes and is charged %d", cap(d.buf), cap(d.tsdu), d.charged)
					}
					if (d.next != nil) != (d.charged > 0) {
						t.Fatalf("a direction charged %d bytes is listed: %v", d.charged, d.next != nil)
					}
					if d.charged > 0 {
						holding++
					}
					total += d.charged
				}
			}
			if total != a.heldLen || holding != listed || a.heldLen > budget {
				t.Fatalf("%d bytes charged, %d held by %d directions, %d listed, budget %d", a.heldLen, total, holding, listed, budget)
			}
		}
		for i := 0; i+3 <= len(in) && i < 3*2000; i += 3 {
			ci, di := int(in[i]>>2&1), int(in[i]&1)
			c, st := conns[ci], &dirs[ci][di]
			n := int(in[i+1]) + 1
			switch in[i] >> 1 & 1 {
			case 0: // the next bytes of the script
				if left := stream[st.sent:]; len(left) > 0 {
					b := left[:min(n, len(left))]
					a.Data(c, di, st.pos, bytes.Clone(b), flow.Chunk{Frame: uint64(i/3 + 1), TimeNS: int64(i + 1)})
					st.sent += len(b)
					st.pos += uint64(len(b))
				}
			default:
				st.clean = false
				if in[i+2]&1 == 0 { // a hole: the next bytes of the script are skipped
					skip := min(n, len(stream)-st.sent)
					if skip == 0 {
						break
					}
					st.sent += skip
					a.Gap(c, di, st.pos, int64(skip), flow.GapLoss)
					st.pos += uint64(skip)
				} else { // bytes of the input instead
					b := in[i : i+min(n, len(in)-i)]
					a.Data(c, di, st.pos, bytes.Clone(b), flow.Chunk{Frame: uint64(i/3 + 1), TimeNS: int64(i + 1)})
					st.pos += uint64(len(b))
				}
			}
			check()
		}
		found := map[int]int{} // association ID to its reports
		for _, r := range a.res.Reports {
			found[r.Association]++
		}
		for ci, c := range conns {
			cs := c.User.(*conn)
			want := 0
			clean := budget == DefaultMaxAssembly
			for di := range dirs[ci] {
				clean = clean && dirs[ci][di].clean
				want += len(ends) - len(slices.DeleteFunc(slices.Clone(ends), func(e int) bool { return e <= dirs[ci][di].sent }))
			}
			got := 0
			if cs.assoc != nil {
				got = found[cs.assoc.ID]
			}
			if clean && got != want {
				t.Fatalf("connection %d got its scripts without a hole: %d PDUs found, %d sent whole", ci, got, want)
			}
		}
		if clean := dirs[0][0].clean && dirs[0][1].clean && dirs[1][0].clean && dirs[1][1].clean; clean && budget == DefaultMaxAssembly {
			if cn := a.res.Counters; cn.TPKTResync+cn.COTPErrors+cn.TSDUErrors != 0 {
				t.Fatalf("counters %+v for scripts delivered without a hole", cn)
			}
		}
		for _, c := range conns {
			a.Close(c)
		}
		check()
		if a.heldLen != 0 {
			t.Fatalf("%d bytes charged after every connection closed", a.heldLen)
		}
	})
}
