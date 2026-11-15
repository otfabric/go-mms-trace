// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type fuzzPacket struct {
	offset int64
	frame  uint64
	n      int
}

// fuzzPass reads b to the end of the read with a limit on the bytes read
// (0: the default) and returns the packets, the reader and the error that
// ended the read. Every packet is within the limits.
func fuzzPass(t *testing.T, b []byte, maxBytes int64) ([]fuzzPacket, *Reader, error) {
	rd, err := NewReader(bytes.NewReader(b), Options{MaxPacket: 4096, MaxBlock: 1 << 16, MaxBytes: maxBytes, MaxInterfaces: 8, MaxSections: 8, MaxText: 64})
	if err != nil {
		if !errors.Is(err, ErrFormat) {
			t.Fatalf("NewReader: %v, not ErrFormat", err)
		}
		return nil, nil, err
	}
	var out []fuzzPacket
	var p Packet
	for {
		if err = rd.Next(&p); err != nil {
			if err != io.EOF {
				if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrLimit) {
					t.Fatalf("Next: %v, neither ErrCorrupt nor ErrLimit", err)
				}
				if rd.Next(&p) != io.EOF {
					t.Fatal("Next after an error must return io.EOF")
				}
			}
			break
		}
		if len(p.Data) > 4096 || uint32(len(p.Data)) != p.CapLen || p.OrigLen < p.CapLen {
			t.Fatalf("packet out of bounds: %d bytes, caplen %d, origlen %d", len(p.Data), p.CapLen, p.OrigLen)
		}
		if p.Offset < 0 || p.Offset+int64(len(p.Data)) > rd.Offset() || p.Frame == 0 {
			t.Fatalf("frame %d at offset %d with %d bytes, %d bytes read", p.Frame, p.Offset, len(p.Data), rd.Offset())
		}
		if int(p.Iface) >= len(rd.Interfaces()) {
			t.Fatalf("frame %d on interface %d of %d", p.Frame, p.Iface, len(rd.Interfaces()))
		}
		out = append(out, fuzzPacket{p.Offset, p.Frame, len(p.Data)})
		if len(out) > len(b)*1024 {
			t.Fatal("more packets than the input can hold")
		}
	}
	text := 0
	for _, f := range rd.Interfaces() {
		text += len(f.Name) + len(f.Description) + len(f.OS)
	}
	for _, s := range rd.Sections() {
		text += len(s.Comment) + len(s.Hardware) + len(s.OS) + len(s.Application)
	}
	if len(rd.Interfaces()) > 8 || len(rd.Sections()) > 8 || text > 64 {
		t.Fatalf("%d interfaces, %d sections, %d bytes of text kept: more than the limits", len(rd.Interfaces()), len(rd.Sections()), text)
	}
	return out, rd, err
}

// fuzzRead reads everything, checks the bounds of every packet and of what
// the reader keeps, then reads again with a limit of half the bytes the
// first pass read: the second pass gives the same packets up to the limit,
// reads no byte past it and ends with ErrLimit.
func fuzzRead(t *testing.T, b []byte) {
	all, rd, _ := fuzzPass(t, b, 0)
	if rd == nil {
		return
	}
	total := rd.Offset()
	limit := total / 2
	if limit == 0 {
		return
	}
	bound := limit
	if rd.Format() == Pcap {
		bound = max(bound, 24) // the file header is read whatever the limit
	}
	part, rd2, err := fuzzPass(t, b, limit)
	if rd2.Offset() > bound {
		t.Fatalf("%d bytes read with a limit of %d", rd2.Offset(), limit)
	}
	if len(part) > len(all) {
		t.Fatalf("%d packets with a limit, %d without", len(part), len(all))
	}
	for i, p := range part {
		if p != all[i] {
			t.Fatalf("packet %d with a limit is %+v, without %+v", i, p, all[i])
		}
	}
	if total > bound && !errors.Is(err, ErrLimit) {
		t.Fatalf("the input has %d bytes and the limit is %d, but the read ended with %v", total, limit, err)
	}
}

func FuzzPcapReader(f *testing.F) {
	for _, nanos := range []bool{false, true} {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1, Nanos: nanos, BigEndian: nanos})
		_ = w.WritePacket(t0, 0, []byte("hello"))
		_ = w.WritePacket(t0, 100, []byte("world!"))
		_ = w.Flush()
		f.Add(buf.Bytes())
	}
	f.Fuzz(fuzzRead)
}

func FuzzPcapngReader(f *testing.F) {
	f.Add(ngFile(f, false))
	f.Add(ngFile(f, true))
	f.Add(ngSections(f, 3, "comment"))
	f.Add(ngInterfaces(f, 3, "eth0"))
	f.Fuzz(fuzzRead)
}
