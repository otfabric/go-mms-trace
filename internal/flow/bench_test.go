// SPDX-License-Identifier: MIT

package flow

import (
	"net/netip"
	"testing"

	"github.com/otfabric/go-mms-trace/internal/link"
	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// benchBytes keeps the count of the last pass alive.
var benchBytes int

// BenchmarkTracker measures the TCP stage alone, on segments already
// decoded: 20,000 segments of 200 bytes over 16 connections, in order;
// the same with every second segment held behind its predecessor (out of
// order); and one-byte segments held behind holes of their own with the
// total budget full, where every segment makes a connection give up a hole.
// The throughput is per byte of TCP payload.
func BenchmarkTracker(b *testing.B) {
	const (
		conns = 16
		segs  = 20_000
		size  = 200
	)
	payload := make([]byte, size)
	src := make([]netip.AddrPort, conns)
	for i := range src {
		src[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 40000)
	}
	pkt := &pcapio.Packet{Frame: 1, HasTime: true, TimeNS: 1}
	feed := func(tr *Tracker, order func(i int) int) {
		for c := range conns { // one byte first: where each stream starts
			s := link.Segment{Src: src[c], Dst: svAddr, Seq: 999, Flags: link.ACK, Payload: payload[:1]}
			tr.Packet(pkt, &s)
		}
		for i := range segs / conns {
			for c := range conns {
				s := link.Segment{Src: src[c], Dst: svAddr, Seq: 1000 + uint32(order(i)*size), Flags: link.ACK, Payload: payload}
				tr.Packet(pkt, &s)
			}
		}
		tr.Finish()
	}
	orders := []struct {
		name  string
		order func(i int) int
	}{
		{"in-order", func(i int) int { return i }},
		{"out-of-order", func(i int) int { return i ^ 1 }}, // 1, 0, 3, 2, ...
	}
	for _, o := range orders {
		b.Run(o.name, func(b *testing.B) {
			b.SetBytes(segs * size)
			b.ReportAllocs()
			for b.Loop() {
				h := &counter{}
				feed(NewTracker(Limits{}, h), o.order)
				if h.data != segs*size+conns || h.gaps != 0 {
					b.Fatalf("%d bytes delivered, %d gaps", h.data, h.gaps)
				}
				benchBytes = h.data
			}
		})
	}
	b.Run("budget-full", func(b *testing.B) {
		const (
			cost    = 1 + heldOverhead
			holders = 32
			each    = 16
			extra   = 20_000
		)
		b.SetBytes(extra)
		b.ReportAllocs()
		for b.Loop() {
			h := &counter{}
			tr := NewTracker(Limits{BufferPerDir: 1 << 20, BufferTotal: holders * each * cost}, h)
			for i := range holders {
				holding(tr, i, 100, 1)
				holding(tr, i, 1000, each)
			}
			for j := range extra {
				holding(tr, j%holders, uint32(2000+2*j), 1)
			}
			if tr.Stats.BudgetGaps != extra {
				b.Fatalf("%d budget gaps", tr.Stats.BudgetGaps)
			}
			benchBytes = h.data
		}
	})
}
