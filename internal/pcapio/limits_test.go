// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"runtime"
	"strconv"
	"testing"
)

// TestPcapNGTimestampRange: a pcapng time that does not fit in 64 bits of
// nanoseconds is reported as such, at every edge of the range: the last
// second, the last unit of each resolution, offsets of both signs, the
// limits of the 64-bit fields.
func TestPcapNGTimestampRange(t *testing.T) {
	const (
		lastSec = math.MaxInt64 / 1_000_000_000 // 9223372036: the last whole second that fits
		maxU    = math.MaxUint64
	)
	cases := []struct {
		name   string
		ts     uint64
		resol  byte
		offset int64
		want   int64
		fits   bool
	}{
		{"seconds: zero", 0, 0, 0, 0, true},
		{"seconds: one", 1, 0, 0, 1_000_000_000, true},
		{"seconds: the last that fits", lastSec, 0, 0, lastSec * 1_000_000_000, true},
		{"seconds: one more", lastSec + 1, 0, 0, 0, false},
		{"seconds: 2^63", 1 << 63, 0, 0, 0, false},
		{"seconds: the largest count", maxU, 0, 0, 0, false},
		{"microseconds: the last that fits", math.MaxInt64 / 1000, 6, 0, math.MaxInt64 / 1000 * 1000, true},
		{"microseconds: one more", math.MaxInt64/1000 + 1, 6, 0, 0, false},
		{"microseconds: the largest count", maxU, 6, 0, 0, false},
		{"nanoseconds: one below the last", math.MaxInt64 - 1, 9, 0, math.MaxInt64 - 1, true},
		{"nanoseconds: the last that fits", math.MaxInt64, 9, 0, math.MaxInt64, true},
		{"nanoseconds: one more", math.MaxInt64 + 1, 9, 0, 0, false},
		{"nanoseconds: the largest count", maxU, 9, 0, 0, false},
		{"2^-10 s: the last that fits", lastSec<<10 + 875, 0x80 | 10, 0, lastSec*1_000_000_000 + 854_492_187, true},
		{"2^-10 s: one more", lastSec<<10 + 876, 0x80 | 10, 0, 0, false},
		{"2^-10 s: the largest count", maxU, 0x80 | 10, 0, 0, false},
		{"offset: the last second", 0, 0, lastSec, lastSec * 1_000_000_000, true},
		{"offset: one second more", 0, 0, lastSec + 1, 0, false},
		{"offset: added to the last second", lastSec, 0, 1, 0, false},
		{"offset: the largest", 0, 0, math.MaxInt64, 0, false},
		{"offset: the largest, past the count's range", maxU, 0, 1, 0, false},
		{"offset: negative, back to the last second", lastSec + 5, 0, -5, lastSec * 1_000_000_000, true},
		{"offset: negative, back to zero", 7, 0, -7, 0, true},
		{"offset: before 1970", 0, 0, -lastSec, -lastSec * 1_000_000_000, true},
		{"offset: one above the earliest time", 145_224_193, 9, -lastSec - 1, math.MinInt64 + 1, true},
		{"offset: the earliest time", 145_224_192, 9, -lastSec - 1, math.MinInt64, true},
		{"offset: one before the earliest time", 145_224_191, 9, -lastSec - 1, 0, false},
		{"offset: a second before the earliest second", 0, 0, -lastSec - 2, 0, false},
		{"offset: the smallest", 0, 0, math.MinInt64, 0, false},
		{"offset: the smallest, from 2^63 seconds", 1 << 63, 0, math.MinInt64, 0, true},
		{"offset: the smallest, from the largest count", maxU, 0, math.MinInt64, 0, false},
		{"microseconds with an offset past the range", 1_700_000_000_000_000, 6, 1 << 40, 0, false},
	}
	for _, c := range cases {
		got, fits := toNS(c.ts, c.resol, c.offset)
		if got != c.want || fits != c.fits {
			t.Errorf("%s: toNS(%d, %#x, %d) = %d, fits %v; want %d, fits %v", c.name, c.ts, c.resol, c.offset, got, fits, c.want, c.fits)
		}
	}
}

// epb is the body of an Enhanced Packet Block with a raw timestamp.
func epb(bo binary.AppendByteOrder, iface uint32, ts uint64, data []byte) []byte {
	b := bo.AppendUint32(nil, iface)
	b = bo.AppendUint32(b, uint32(ts>>32))
	b = bo.AppendUint32(b, uint32(ts))
	b = bo.AppendUint32(b, uint32(len(data)))
	b = bo.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// TestTimeOutOfRange: a packet whose time does not fit is read without a
// time and counted; the packets around it keep theirs.
func TestTimeOutOfRange(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 1, TSResol: 6}, {LinkType: 1, TSResol: 6, TSOffset: 1 << 40}})
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	steps := []error{
		w.WritePacket(0, t0, 0, []byte("before")),
		w.WriteBlock(blockEPB, epb(le, 0, math.MaxUint64, []byte("the largest count"))),
		w.WriteBlock(blockEPB, epb(le, 0, math.MaxInt64/1000+1, []byte("one past the last microsecond"))),
		w.WriteBlock(blockEPB, epb(le, 0, math.MaxInt64/1000, []byte("the last microsecond"))),
		w.WriteBlock(blockEPB, epb(le, 1, 1_700_000_000_000_000, []byte("an offset past the range"))),
		w.WritePacket(0, t0+1000, 0, []byte("after")),
		w.Flush(),
	}
	for i, err := range steps {
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	rd, got, pks, err := readAll(t, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		hasTime bool
		ns      int64
	}{{true, t0 / 1000 * 1000}, {false, 0}, {false, 0}, {true, math.MaxInt64 / 1000 * 1000}, {false, 0}, {true, (t0 + 1000) / 1000 * 1000}}
	if len(got) != len(want) {
		t.Fatalf("%d packets, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].hasTime != w.hasTime || got[i].timeNS != w.ns || pks[i].Frame != uint64(i+1) {
			t.Errorf("packet %d (%q): time %d, has time %v; want %d, %v", i, got[i].data, got[i].timeNS, got[i].hasTime, w.ns, w.hasTime)
		}
	}
	if c := rd.Counters(); c.BadTimestamps != 3 || c.SimplePackets != 0 || c.SkippedBlocks != 0 {
		t.Errorf("counters %+v, want 3 bad timestamps", c)
	}
}

// captures returns a pcap and a pcapng file with the same packets.
func captures(t testing.TB, packets ...[]byte) map[string][]byte {
	t.Helper()
	var pc, ng bytes.Buffer
	pw, err := NewPcapWriter(&pc, PcapOptions{LinkType: 1, Nanos: true})
	if err != nil {
		t.Fatal(err)
	}
	nw, err := NewNgWriter(&ng, Section{}, []Interface{{LinkType: 1, TSResol: 9}})
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range packets {
		if err := errors.Join(pw.WritePacket(t0+int64(i), 0, p), nw.WritePacket(0, t0+int64(i), 0, p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(pw.Flush(), nw.Flush()); err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"pcap": pc.Bytes(), "pcapng": ng.Bytes()}
}

// count reads a file to its end and returns the packets read and the error
// that ended the read (nil at the end of the input).
func count(t testing.TB, r io.Reader, o Options) (*Reader, int, error) {
	t.Helper()
	rd, err := NewReader(r, o)
	if err != nil {
		t.Fatal(err)
	}
	var p Packet
	n := 0
	for {
		if err := rd.Next(&p); err != nil {
			if err == io.EOF {
				err = nil
			} else if rd.Next(&p) != io.EOF {
				t.Fatal("Next after an error is not io.EOF")
			}
			return rd, n, err
		}
		n++
	}
}

// TestMaxPacketRange: Options.MaxPacket bounds a packet record at every
// value an int can have. A value above the 32 bits a record length has
// bounds nothing; it does not turn into a small limit.
func TestMaxPacketRange(t *testing.T) {
	const size = 100
	limits := []struct {
		max  int
		read bool
	}{{-1, true}, {0, true}, {1, false}, {size - 1, false}, {size, true}, {size + 1, true}, {DefaultMaxPacket, true}, {math.MaxInt32, true}}
	if strconv.IntSize == 64 {
		// Values an int of 32 bits cannot hold: computed, so that the test
		// compiles for those platforms too.
		two32 := uint64(1) << 32
		for _, v := range []uint64{two32 - 1, two32, two32 + 1, two32 + size - 1, two32 + size, 1 << 62, math.MaxInt64} {
			limits = append(limits, struct {
				max  int
				read bool
			}{int(v), true})
		}
	}
	for name, file := range captures(t, make([]byte, 10), make([]byte, size), make([]byte, 20)) {
		for _, l := range limits {
			rd, n, err := count(t, bytes.NewReader(file), Options{MaxPacket: l.max})
			switch {
			case l.read:
				if n != 3 || err != nil || rd.Counters().SkippedBlocks != 0 {
					t.Errorf("%s, MaxPacket %d: %d packets, %d skipped, err %v; want 3 packets", name, l.max, n, rd.Counters().SkippedBlocks, err)
				}
			case name == "pcap": // a record past the limit ends a pcap file
				if want := min(1, l.max/10); n != want || !errors.Is(err, ErrCorrupt) {
					t.Errorf("pcap, MaxPacket %d: %d packets, err %v; want %d and ErrCorrupt", l.max, n, err, want)
				}
			default: // and is skipped in a pcapng file
				if want := 2 * min(1, l.max/10); n != want || err != nil || rd.Counters().SkippedBlocks != uint64(3-want) {
					t.Errorf("pcapng, MaxPacket %d: %d packets, %d skipped, err %v; want %d packets", l.max, n, rd.Counters().SkippedBlocks, err, want)
				}
			}
		}
	}
}

// allocated returns the bytes fn allocates.
func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() int64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// TestSizeLimits is the allocation budget of the record and block limits
// (Options.MaxPacket, Options.MaxBlock): an input that declares a record,
// a block or a section header of any length and does not hold it costs the
// reader its fixed buffers and no more, at the limits, one past them, and
// with the limits raised to what the 32-bit length fields can declare.
func TestSizeLimits(t *testing.T) {
	le := binary.LittleEndian
	pcapRecord := func(capLen uint32) []byte { // a file header, a record header and ten bytes
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
		_ = w.Flush()
		b := le.AppendUint32(buf.Bytes(), 1)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, capLen)
		b = le.AppendUint32(b, capLen)
		return append(b, make([]byte, 10)...)
	}
	ngBlock := func(typ, n uint32) []byte { // a section, then a block header of length n and ten bytes
		var buf bytes.Buffer
		w, _ := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 1}})
		_ = w.Flush()
		b := le.AppendUint32(buf.Bytes(), typ)
		b = le.AppendUint32(b, n)
		return append(b, make([]byte, 10)...)
	}
	shb := func(n uint32) []byte { // a section header of length n, cut after its magic
		b := le.AppendUint32(nil, blockSHB)
		b = le.AppendUint32(b, n)
		return le.AppendUint32(b, 0x1A2B3C4D)
	}
	const (
		fixed = 1 << 20 // two 256 KiB read buffers at most, the 64 KiB packet buffer, the hash
		big   = 1 << 30
	)
	cases := []struct {
		name    string
		file    []byte
		o       Options
		corrupt bool // the length is past the limit: ErrCorrupt; else a cut-short tail
	}{
		{"pcap record at the default limit", pcapRecord(DefaultMaxPacket), Options{}, false},
		{"pcap record one past the default limit", pcapRecord(DefaultMaxPacket + 1), Options{}, true},
		{"pcap record of 1 GiB with the limit raised to it", pcapRecord(big), Options{MaxPacket: big}, false},
		{"pcap record of 2 GiB with the limit raised to 1 GiB", pcapRecord(2 * big), Options{MaxPacket: big}, true},
		{"pcap record of the largest length", pcapRecord(math.MaxUint32), Options{}, true},
		{"pcapng block at the default limit", ngBlock(blockEPB, DefaultMaxBlock), Options{}, false},
		{"pcapng block one step past the default limit", ngBlock(blockEPB, DefaultMaxBlock+4), Options{}, true},
		{"pcapng block of 1 GiB with the limit raised to it", ngBlock(0x99, big), Options{MaxBlock: big}, false},
		{"pcapng block of the largest length", ngBlock(blockEPB, math.MaxUint32-3), Options{}, true},
		{"pcapng section header at the default limit", shb(DefaultMaxBlock), Options{}, false},
		{"pcapng section header one step past the default limit", shb(DefaultMaxBlock + 4), Options{}, true},
		{"pcapng section header of 1 GiB with the limit raised to it", shb(big), Options{MaxBlock: big}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rd *Reader
			var err error
			n := allocated(func() { rd, _, err = count(t, bytes.NewReader(tc.file), tc.o) })
			if tc.corrupt != errors.Is(err, ErrCorrupt) || (!tc.corrupt && (err != nil || !rd.Counters().TruncatedTail)) {
				t.Errorf("err %v, truncated tail %v; want ErrCorrupt %v", err, rd.Counters().TruncatedTail, tc.corrupt)
			}
			if n > fixed {
				t.Errorf("%d bytes allocated for an input of %d bytes: more than the %d of the reader's fixed buffers", n, len(tc.file), fixed)
			}
		})
	}
}

// TestLargeRecords: a record or block larger than the reader's first
// buffer is read whole, in a pcap and in a pcapng file, plain and gzip.
func TestLargeRecords(t *testing.T) {
	big := make([]byte, 300<<10)
	for i := range big {
		big[i] = byte(i * 7)
	}
	for name, file := range captures(t, []byte("small"), big, big[:70<<10], []byte("last")) {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(file)
		_ = zw.Close()
		for form, in := range map[string][]byte{"plain": file, "gzip": gz.Bytes()} {
			rd, err := NewReader(bytes.NewReader(in), Options{MaxPacket: 512 << 10})
			if err != nil {
				t.Fatal(err)
			}
			var p Packet
			var got [][]byte
			for rd.Next(&p) == nil {
				got = append(got, bytes.Clone(p.Data))
			}
			if len(got) != 4 || !bytes.Equal(got[1], big) || !bytes.Equal(got[2], big[:70<<10]) || string(got[3]) != "last" {
				t.Errorf("%s, %s: %d packets read, or not as written", name, form, len(got))
			}
			if rd.Offset() != int64(len(file)) {
				t.Errorf("%s, %s: offset %d at the end of %d bytes", name, form, rd.Offset(), len(file))
			}
		}
	}
}

// TestMaxBytes: Options.MaxBytes bounds the bytes read from the input,
// counted after decompression. An input that ends at or before the limit is
// read as without one; an input that goes on past it ends with ErrLimit
// before the first record or block that does not fit, and the reader never
// reads past the limit.
func TestMaxBytes(t *testing.T) {
	packets := [][]byte{make([]byte, 40), make([]byte, 60), make([]byte, 80)}
	for name, file := range captures(t, packets...) {
		size := int64(len(file))
		lastStart := size - 80 - 16 // start of the last pcap record
		if name == "pcapng" {
			lastStart = size - (12 + 20 + 80)
		}
		var gz, gz2 bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(file)
		_ = zw.Close()
		for _, part := range [][]byte{file[:50], file[50:]} { // the same bytes in two gzip members
			zw := gzip.NewWriter(&gz2)
			_, _ = zw.Write(part)
			_ = zw.Close()
		}
		cases := []struct {
			max     int64
			packets int
			limit   bool
		}{
			{0, 3, false}, {-1, 3, false}, {math.MaxInt64, 3, false},
			{size + 1, 3, false}, {size, 3, false}, {size - 1, 2, true},
			{lastStart + 1, 2, true}, {lastStart, 2, true}, {lastStart - 1, 1, true},
			{30, 0, true}, {24, 0, true}, {1, 0, true},
		}
		for form, in := range map[string][]byte{"plain": file, "gzip": gz.Bytes(), "gzip in two members": gz2.Bytes()} {
			for _, tc := range cases {
				rd, n, err := count(t, bytes.NewReader(in), Options{MaxBytes: tc.max})
				if n != tc.packets || errors.Is(err, ErrLimit) != tc.limit || (err != nil && !tc.limit) || errors.Is(err, ErrCorrupt) {
					t.Errorf("%s, %s, MaxBytes %d: %d packets, err %v; want %d packets, ErrLimit %v", name, form, tc.max, n, err, tc.packets, tc.limit)
				}
				bound := tc.max
				if bound <= 0 {
					bound = DefaultMaxBytes
				}
				if name == "pcap" {
					bound = max(bound, 24) // the file header is read whatever the limit
				}
				if off := rd.Offset(); off > bound || (!tc.limit && off != size) {
					t.Errorf("%s, %s, MaxBytes %d: %d bytes read of %d", name, form, tc.max, off, size)
				}
				if rd.Counters().TruncatedTail {
					t.Errorf("%s, %s, MaxBytes %d: a truncated tail", name, form, tc.max)
				}
			}
		}
		// An input that ends inside a record exactly at the limit, before
		// it and after it is a cut-short tail, as without a limit.
		for _, cut := range []int64{size - 1, size - 40, lastStart + 5} {
			for _, max := range []int64{cut - 1, cut, cut + 1} {
				rd, n, err := count(t, bytes.NewReader(file[:cut]), Options{MaxBytes: max})
				wantLimit := max < cut
				if n != 2 || errors.Is(err, ErrLimit) != wantLimit || rd.Counters().TruncatedTail == wantLimit {
					t.Errorf("%s cut at %d, MaxBytes %d: %d packets, err %v, truncated tail %v", name, cut, max, n, err, rd.Counters().TruncatedTail)
				}
			}
		}
	}
}

// ngInterfaces is a pcapng file with n interfaces, each named name and
// followed by one packet captured on it.
func ngInterfaces(t testing.TB, n int, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := errors.Join(w.AddInterface(Interface{LinkType: 1, Name: name}), w.WritePacket(uint32(i), t0, 0, []byte{byte(i)})); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestInterfaceLimit: the reader keeps at most Options.MaxInterfaces
// interfaces of an input. A further one is skipped with the packets
// captured on it, and counted.
func TestInterfaceLimit(t *testing.T) {
	for _, tc := range []struct{ limit, have int }{{3, 0}, {3, 2}, {3, 3}, {3, 4}, {3, 50}, {1, 2}, {0, 5},
		{0, DefaultMaxInterfaces}, {0, DefaultMaxInterfaces + 1}} {
		rd, n, err := count(t, bytes.NewReader(ngInterfaces(t, tc.have, "eth")), Options{MaxInterfaces: tc.limit})
		want := tc.limit
		if want == 0 {
			want = DefaultMaxInterfaces
		}
		want = min(want, tc.have)
		if err != nil || n != want || len(rd.Interfaces()) != want || rd.Counters().SkippedBlocks != uint64(2*(tc.have-want)) {
			t.Errorf("limit %d, %d interfaces in the file: %d kept, %d packets, %d blocks skipped, err %v; want %d kept", tc.limit, tc.have,
				len(rd.Interfaces()), n, rd.Counters().SkippedBlocks, err, want)
		}
	}
	// The limit is over all sections of the input.
	var buf bytes.Buffer
	w, _ := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 1}, {LinkType: 1}})
	_ = w.WritePacket(1, t0, 0, []byte("a"))
	_ = w.NewSection(Section{}, []Interface{{LinkType: 1}, {LinkType: 1}})
	_ = w.WritePacket(0, t0, 0, []byte("b"))
	_ = w.WritePacket(1, t0, 0, []byte("c")) // on the fourth interface
	_ = w.NewSection(Section{}, []Interface{{LinkType: 1}})
	_ = w.WritePacket(0, t0, 0, []byte("d")) // on the fifth
	_ = w.WriteSimplePacket(0, []byte("e"))  // the first interface of a section that has none
	_ = w.Flush()
	rd, n, err := count(t, bytes.NewReader(buf.Bytes()), Options{MaxInterfaces: 3})
	if err != nil || n != 2 || len(rd.Interfaces()) != 3 || rd.Counters().SkippedBlocks != 5 {
		t.Errorf("three sections: %d interfaces, %d packets, %d blocks skipped, err %v", len(rd.Interfaces()), n, rd.Counters().SkippedBlocks, err)
	}
}

// ngSections is a pcapng file of n sections with one packet each.
func ngSections(t testing.TB, n int, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{Comment: comment}, []Interface{{LinkType: 1}})
	for i := range n {
		if i > 0 {
			err = errors.Join(err, w.NewSection(Section{Comment: comment}, []Interface{{LinkType: 1}}))
		}
		err = errors.Join(err, w.WritePacket(0, t0, 0, []byte{byte(i)}))
	}
	if err = errors.Join(err, w.Flush()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSectionLimit: the reader reads at most Options.MaxSections sections
// of an input. A further section header ends the read with ErrLimit; what
// was read before stands.
func TestSectionLimit(t *testing.T) {
	for _, tc := range []struct{ limit, have int }{{3, 1}, {3, 2}, {3, 3}, {3, 4}, {3, 40}, {1, 2}, {0, 5},
		{0, DefaultMaxSections}, {0, DefaultMaxSections + 1}} {
		rd, n, err := count(t, bytes.NewReader(ngSections(t, tc.have, "")), Options{MaxSections: tc.limit})
		want := tc.limit
		if want == 0 {
			want = DefaultMaxSections
		}
		over := tc.have > want
		want = min(want, tc.have)
		if n != want || len(rd.Sections()) != want || errors.Is(err, ErrLimit) != over || (err != nil && !over) || errors.Is(err, ErrCorrupt) {
			t.Errorf("limit %d, %d sections in the file: %d read, %d packets, err %v; want %d, ErrLimit %v", tc.limit, tc.have,
				len(rd.Sections()), n, err, want, over)
		}
	}
}

// TestTextLimit: the reader keeps at most Options.MaxText bytes of option
// text of an input. Text past it is left out and counted; its interface
// or section is kept.
func TestTextLimit(t *testing.T) {
	for _, tc := range []struct{ limit, kept int }{{11, 0}, {12, 1}, {13, 1}, {23, 1}, {24, 2}, {59, 4}, {60, 5}, {61, 5}, {0, 5}} {
		rd, n, err := count(t, bytes.NewReader(ngInterfaces(t, 5, "twelve bytes")), Options{MaxText: tc.limit})
		named := 0
		for _, f := range rd.Interfaces() {
			if f.Name == "twelve bytes" {
				named++
			} else if f.Name != "" {
				t.Errorf("limit %d: name %q", tc.limit, f.Name)
			}
		}
		if err != nil || n != 5 || len(rd.Interfaces()) != 5 || named != tc.kept || rd.Counters().BadOptions != uint64(5-tc.kept) {
			t.Errorf("limit %d: %d interfaces, %d named, %d packets, %d options counted, err %v; want %d named", tc.limit,
				len(rd.Interfaces()), named, n, rd.Counters().BadOptions, err, tc.kept)
		}
	}
	rd, _, err := count(t, bytes.NewReader(ngSections(t, 4, "ten bytes.")), Options{MaxText: 25})
	if err != nil || len(rd.Sections()) != 4 || rd.Sections()[1].Comment != "ten bytes." || rd.Sections()[2].Comment != "" || rd.Counters().BadOptions != 2 {
		t.Errorf("sections %+v, counters %+v, err %v", rd.Sections(), rd.Counters(), err)
	}
}

// TestOptionsAreaLimit: an options area of at most 64 KiB is parsed; a
// larger one is ignored as a whole and counted, and its block is used
// without its options.
func TestOptionsAreaLimit(t *testing.T) {
	le := binary.LittleEndian
	idb := func(area int) []byte { // an interface block whose options are a name and comments up to area bytes
		b := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		b = append(b, 2, 0, 4, 0, 'e', 't', 'h', '0')
		for len(b)-8 < area-4 {
			n := min(4000, area-4-(len(b)-8)-4)
			b = le.AppendUint16(le.AppendUint16(b, 1), uint16(n))
			b = append(b, make([]byte, n)...)
		}
		return append(b, 0, 0, 0, 0)
	}
	for _, tc := range []struct {
		area int
		name string
		bad  uint64
	}{{maxOptions - 4, "eth0", 0}, {maxOptions, "eth0", 0}, {maxOptions + 4, "", 1}, {4 * maxOptions, "", 1}} {
		var buf bytes.Buffer
		w, _ := NewNgWriter(&buf, Section{}, nil)
		body := idb(tc.area)
		if len(body)-8 != tc.area {
			t.Fatalf("an options area of %d bytes, want %d", len(body)-8, tc.area)
		}
		_ = w.WriteBlock(blockIDB, body)
		_ = w.WriteBlock(blockEPB, epb(le, 0, 1_000_000, []byte("packet")))
		_ = w.Flush()
		rd, n, err := count(t, bytes.NewReader(buf.Bytes()), Options{MaxBlock: 1 << 20})
		if err != nil || n != 1 || len(rd.Interfaces()) != 1 || rd.Interfaces()[0].Name != tc.name || rd.Counters().BadOptions != tc.bad {
			t.Errorf("an options area of %d bytes: %d packets, interfaces %+v, %d bad options, err %v", tc.area, n, rd.Interfaces(), rd.Counters().BadOptions, err)
		}
	}
}

// TestMetadataBudget is the allocation budget of the interface, section
// and text limits: what the reader holds after an input with many times
// the limit of each, as live heap, is what the limits allow and the
// reader's fixed buffers.
func TestMetadataBudget(t *testing.T) {
	const (
		limit = 500
		text  = 32 << 10
		fixed = 1 << 20
	)
	name := string(bytes.Repeat([]byte("n"), 1000))
	for kind, file := range map[string][]byte{"interfaces": ngInterfaces(t, 40*limit, name), "sections": ngSections(t, 40*limit, name)} {
		in := bytes.NewReader(file)
		before := liveHeap()
		rd, _, err := count(t, in, Options{MaxInterfaces: limit, MaxSections: limit, MaxText: text})
		held := liveHeap() - before
		if kind == "sections" != errors.Is(err, ErrLimit) || len(rd.Interfaces()) > limit || len(rd.Sections()) > limit {
			t.Errorf("%s: %d interfaces, %d sections, err %v", kind, len(rd.Interfaces()), len(rd.Sections()), err)
		}
		// An interface is about 130 bytes and a section 70, in lists that
		// grow by doubling.
		if budget := int64(fixed + text + 2*limit*200); held > budget {
			t.Errorf("%s: %d bytes live after an input of %d bytes with %d of them, budget %d", kind, held, len(file), 40*limit, budget)
		}
		runtime.KeepAlive(rd)
	}
}

// failing is a reader that fails with err after n bytes of data.
type failing struct {
	data []byte
	n    int
	err  error
}

func (f *failing) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, f.err
	}
	n := copy(p, f.data[:min(f.n, len(f.data))])
	f.data, f.n = f.data[n:], f.n-n
	return n, nil
}

// TestStartErrors: an input that cannot be read far enough to tell its
// format is not a capture as far as the reader knows (ErrFormat), and the
// error keeps the read error as its cause; an input that ends there has no
// cause.
func TestStartErrors(t *testing.T) {
	cause := errors.New("device gone")
	files := captures(t, []byte("packet"))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(files["pcap"])
	_ = zw.Close()
	for _, tc := range []struct {
		name string
		data []byte
		n    int
	}{
		{"at the first byte", files["pcap"], 0},
		{"inside the magic number", files["pcap"], 3},
		{"inside the pcap file header", files["pcap"], 10},
		{"inside the gzip header", gz.Bytes(), 5},
		{"inside the gzip stream", gz.Bytes(), 12},
	} {
		_, err := NewReader(&failing{tc.data, tc.n, cause}, Options{})
		if !errors.Is(err, ErrFormat) || !errors.Is(err, cause) || errors.Is(err, ErrCorrupt) {
			t.Errorf("a read error %s: %v; want ErrFormat and the cause", tc.name, err)
		}
		_, err = NewReader(bytes.NewReader(tc.data[:tc.n]), Options{})
		if !errors.Is(err, ErrFormat) || errors.Is(err, cause) || errors.Is(err, io.EOF) {
			t.Errorf("the end of the input %s: %v; want ErrFormat alone", tc.name, err)
		}
	}
	// After the format is known a read error is damage: ErrCorrupt and the cause.
	for name, file := range files {
		_, n, err := count(t, &failing{file, len(file) - 3, cause}, Options{})
		if n != 0 || !errors.Is(err, ErrCorrupt) || !errors.Is(err, cause) || errors.Is(err, ErrFormat) {
			t.Errorf("%s, a read error inside the packet: %d packets, %v", name, n, err)
		}
	}
}
