// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
)

var fragKey = FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 1, Proto: 6}

// TestDefragLastFragment: the last fragment gives the datagram its length,
// whatever the order the fragments arrive in. A last fragment that ends
// before bytes already held is FragmentBad and its datagram is given up; a
// fragment that ends past a length already known is FragmentBad and the
// datagram stays. Each case ends with nothing held.
func TestDefragLastFragment(t *testing.T) {
	type frag struct {
		off  int
		more bool
		n    int
		want Reason
	}
	cases := []struct {
		name  string
		frags []frag
		total int // length of the datagram the last step returns; -1: none
	}{
		{"last ends after the bytes held", []frag{{0, true, 16, FragmentHeld}, {16, false, 8, OK}}, 24},
		{"last ends where the bytes held end", []frag{{0, true, 16, FragmentHeld}, {8, false, 8, OK}}, 16},
		{"last ends one byte before the bytes held end", []frag{{0, true, 16, FragmentHeld}, {8, false, 7, FragmentBad}}, -1},
		{"last at the same offset, shorter", []frag{{0, true, 16, FragmentHeld}, {0, false, 8, FragmentBad}}, -1},
		{"last at the same offset, one byte", []frag{{8, true, 8, FragmentHeld}, {8, false, 1, FragmentBad}}, -1},
		{"last at a lower offset, ends inside the bytes held", []frag{{8, true, 16, FragmentHeld}, {0, false, 9, FragmentBad}}, -1},
		{"last at a lower offset, ends where the bytes held start", []frag{{16, true, 16, FragmentHeld}, {8, false, 8, FragmentBad}}, -1},
		{"last before two held fragments", []frag{{0, true, 16, FragmentHeld}, {16, true, 16, FragmentHeld}, {0, false, 9, FragmentBad}}, -1},
		{"last between two held fragments", []frag{{0, true, 8, FragmentHeld}, {24, true, 8, FragmentHeld}, {8, false, 16, FragmentBad}}, -1},
		{"last first, then a fragment past it, then the rest", []frag{{16, false, 8, FragmentHeld}, {16, true, 24, FragmentBad}, {0, true, 16, OK}}, 24},
		{"last first, then a fragment to its end", []frag{{16, false, 8, FragmentHeld}, {0, true, 24, OK}}, 24},
		{"last first, then one byte past it", []frag{{8, false, 8, FragmentHeld}, {0, true, 24, FragmentBad}, {0, true, 8, OK}}, 16},
		{"a datagram of the largest size", []frag{{0, true, 65528, FragmentHeld}, {65528, false, 7, OK}}, 65535},
		{"last ends past the largest size", []frag{{0, true, 65528, FragmentHeld}, {65528, false, 8, FragmentBad}, {65528, false, 7, OK}}, 65535},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewDefrag(1 << 20)
			var out []byte
			for i, fr := range tc.frags {
				var r Reason
				out, r = f.Add(fragKey, fr.off, fr.more, bytes.Repeat([]byte{byte('a' + i)}, fr.n))
				if r != fr.want {
					t.Fatalf("fragment %d (offset %d, %d bytes, more %v): %v, want %v", i, fr.off, fr.n, fr.more, r, fr.want)
				}
			}
			if tc.total < 0 && out != nil || tc.total >= 0 && len(out) != tc.total {
				t.Errorf("the last step returned %d bytes, want %d", len(out), tc.total)
			}
			if f.used != 0 || f.Pending != 0 || len(f.m) != 0 {
				t.Errorf("held at the end: %d bytes charged, %d pending, %d datagrams", f.used, f.Pending, len(f.m))
			}
		})
	}
}

// TestDecodeLastFragment: the same through the decoder, for IPv4 and IPv6:
// two fragments are held, a last fragment that ends before them is counted
// as fragment_bad, and the decoder goes on with the next datagram.
func TestDecodeLastFragment(t *testing.T) {
	v4 := func(id uint16, off int, more bool, payload []byte) []byte {
		b := ipv4(6, 0, payload)
		binary.BigEndian.PutUint16(b[4:], id)
		fo := uint16(off / 8)
		if more {
			fo |= 0x2000
		}
		binary.BigEndian.PutUint16(b[6:], fo)
		return b
	}
	v6 := func(id uint32, off int, more bool, payload []byte) []byte {
		h := []byte{6, 0, 0, 0, 0, 0, 0, 0}
		fo := uint16(off)
		if more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(h[2:], fo)
		binary.BigEndian.PutUint32(h[4:], id)
		return ipv6(44, append(h, payload...))
	}
	whole := tcp("0123456789abcdef0123") // 20 bytes of header, 20 of payload
	for name, frag := range map[string]func(id, off int, more bool, payload []byte) []byte{
		"IPv4": func(id, off int, more bool, p []byte) []byte { return v4(uint16(id), off, more, p) },
		"IPv6": func(id, off int, more bool, p []byte) []byte { return v6(uint32(id), off, more, p) },
	} {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(1 << 16)
			var s Segment
			steps := []struct {
				pkt  []byte
				want Reason
			}{
				{frag(7, 0, true, whole[:16]), FragmentHeld},
				{frag(7, 16, true, whole[16:32]), FragmentHeld},
				{frag(7, 8, false, whole[8:9]), FragmentBad},
				// The datagram was given up: its fragments start a new one.
				{frag(7, 32, false, whole[32:]), FragmentHeld},
				{frag(8, 0, true, whole[:32]), FragmentHeld},
				{frag(8, 32, false, whole[32:]), OK},
			}
			for i, st := range steps {
				if r := d.Decode(LinkRaw, st.pkt, &s); r != st.want {
					t.Fatalf("packet %d: %v, want %v", i, r, st.want)
				}
			}
			if string(s.Payload) != "0123456789abcdef0123" || s.PayOff != -1 {
				t.Errorf("payload %q at %d", s.Payload, s.PayOff)
			}
			if d.Counts[FragmentBad] != 1 || d.Defrag().Pending != 1 || d.Defrag().Datagrams != 1 {
				t.Errorf("fragment_bad %d, pending %d, datagrams %d", d.Counts[FragmentBad], d.Defrag().Pending, d.Defrag().Datagrams)
			}
		})
	}
}

// checkDefrag fails when the reassembler's accounting does not add up:
// the bytes charged are those of the datagrams held and within the budget,
// every datagram's parts are in offset order and inside its length.
func checkDefrag(t *testing.T, f *Defrag) {
	t.Helper()
	sum := 0
	for k, d := range f.m {
		size, end := datagramOverhead, 0
		for i, p := range d.parts {
			size += len(p.data) + fragOverhead
			end = max(end, p.off+len(p.data))
			if i > 0 && p.off < d.parts[i-1].off {
				t.Fatalf("datagram %d: parts out of order", k.ID)
			}
		}
		if size != d.size || end != d.end || (d.total >= 0 && d.end > d.total) || len(d.parts) == 0 {
			t.Fatalf("datagram %d: size %d (charged %d), end %d (kept %d), total %d, %d parts", k.ID, size, d.size, end, d.end, d.total, len(d.parts))
		}
		sum += size
	}
	if sum != f.used || f.used > f.max || f.Pending != len(f.m) {
		t.Fatalf("%d bytes charged, %d held, budget %d; %d pending, %d datagrams", f.used, sum, f.max, f.Pending, len(f.m))
	}
}

// defragModel is the reassembly rule written out for the fuzz target: the
// fragments of a datagram in arrival order, and for every byte the fragment
// that gives it (the lowest offset, and of equal offsets the first).
type defragModel struct {
	frags []modelFrag
}

type modelFrag struct {
	off, n int
	mark   byte
	last   bool
}

// total is the length the datagram's last fragment gives, or -1.
func (m *defragModel) total() int {
	for _, fr := range m.frags {
		if fr.last {
			return fr.off + fr.n
		}
	}
	return -1
}

func (m *defragModel) byteAt(i int) (byte, bool) {
	best := -1
	for j, fr := range m.frags {
		if fr.off <= i && i < fr.off+fr.n && (best < 0 || fr.off < m.frags[best].off) {
			best = j
		}
	}
	if best < 0 {
		return 0, false
	}
	return m.frags[best].mark, true
}

// FuzzDefragSequence feeds a sequence of fragments of a few datagrams to the
// reassembler. Each fragment is four bytes of input: the datagram and
// flags, the offset, the length. After every fragment the accounting adds
// up and stays within the budget, and a datagram that comes out has the
// length its last fragment gave and, byte for byte, the content the rule
// gives (the lowest offset wins, then the first to arrive).
func FuzzDefragSequence(f *testing.F) {
	f.Add([]byte{0x04, 0, 16, 0, 0x04, 2, 16, 0, 0x00, 4, 5, 0})                // in order
	f.Add([]byte{0x00, 4, 5, 0, 0x04, 2, 16, 0, 0x04, 0, 16, 0})                // last first
	f.Add([]byte{0x04, 0, 16, 0, 0x04, 2, 16, 0, 0x00, 0, 9, 0})                // a last fragment before bytes held
	f.Add([]byte{0x04, 1, 24, 0, 0x04, 0, 16, 0, 0x04, 0, 8, 0, 0x00, 4, 1, 0}) // overlaps
	f.Add([]byte{0x0c, 255, 248, 0, 0x08, 255, 7, 0, 0x08, 255, 8, 0})          // at the largest size
	f.Add([]byte{0x05, 0, 200, 0, 0x06, 0, 200, 0, 0x07, 0, 200, 0, 0x04, 0, 200, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		const budget = 2048
		d := NewDefrag(budget)
		models := map[FragKey]*defragModel{}
		for i := 0; i+4 <= len(in) && i < 4*512; i += 4 {
			k := fragKey
			k.ID = uint32(in[i] & 3)
			more := in[i]&4 != 0
			off := int(in[i+1]) * 8
			if in[i]&8 != 0 {
				off += 65535 - 255*8 - 7 // the last offsets a datagram can have
			}
			n := int(in[i+2])
			mark := byte(i/4 + 1)
			out, r := d.Add(k, off, more, bytes.Repeat([]byte{mark}, n))
			checkDefrag(t, d)
			m := models[k]
			if m == nil {
				m = &defragModel{}
				models[k] = m
			}
			switch r {
			case OK:
				m.frags = append(m.frags, modelFrag{off, n, mark, !more})
				if len(out) != m.total() {
					t.Fatalf("fragment %d: a datagram of %d bytes, its last fragment ends at %d", i/4, len(out), m.total())
				}
				for j, b := range out {
					if want, ok := m.byteAt(j); !ok || b != want {
						t.Fatalf("fragment %d: byte %d of the datagram is of fragment %d, want %d (held %v)", i/4, j, b, want, ok)
					}
				}
			case FragmentHeld:
				m.frags = append(m.frags, modelFrag{off, n, mark, !more})
			case FragmentBad:
			default:
				t.Fatalf("fragment %d: reason %v", i/4, r)
			}
			for key := range models { // datagrams that came out, were given up or dropped by the budget
				if d.m[key] == nil {
					delete(models, key)
				}
			}
		}
	})
}

// TestFragmentBudgetHeap measures what the reassembler holds, as live heap,
// against its budget: fragments of many datagrams, of one datagram, and
// fragments that repeat the same offsets, each many times the budget. The
// heap stays within the budget and what the bookkeeping of one entry costs
// beyond what is charged for it.
func TestFragmentBudgetHeap(t *testing.T) {
	const budget = 1 << 20
	feeds := map[string]func(f *Defrag, i int){
		"many datagrams": func(f *Defrag, i int) {
			k := fragKey
			k.ID = uint32(i)
			f.Add(k, 0, true, make([]byte, 8))
		},
		"datagrams of the most fragments": func(f *Defrag, i int) {
			k := fragKey
			k.ID = uint32(i / 8191)
			f.Add(k, (i%8191)*8, true, make([]byte, 8))
		},
		"the same offset again": func(f *Defrag, i int) {
			k := fragKey
			k.ID = uint32(i % 4)
			f.Add(k, 8, true, make([]byte, 1024))
		},
	}
	for name, feed := range feeds {
		t.Run(name, func(t *testing.T) {
			before := liveHeap()
			f := NewDefrag(budget)
			for i := range 150_000 {
				feed(f, i)
			}
			checkDefrag(t, f)
			held := liveHeap() - before
			// A map entry, an order entry and the slice headers of a part
			// cost at most about twice what is charged for the smallest
			// fragment (72 and 136 bytes).
			if limit := int64(3 * budget); held > limit {
				t.Errorf("%d bytes live with a budget of %d: more than %d", held, budget, limit)
			}
			runtime.KeepAlive(f)
		})
	}
}

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() int64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}
