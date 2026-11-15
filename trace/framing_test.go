// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/otfabric/go-cotp"

	"github.com/otfabric/go-mms-trace/internal/flow"
	"github.com/otfabric/go-mms-trace/internal/link"
	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// restOfPDU is the rest of a PDU whose first bytes are missing: data in
// which the octets 3, 0 are followed by something that reads as a length.
func restOfPDU() []byte {
	var b []byte
	b = append(b, 0xa0, 0x30, 0x84, 0x03, 0x03, 0x00, 0x00, 0x91, 0x08, 1, 2, 3, 4, 5, 6, 7, 8) // a bit string: 3, 0 and a length of 145
	b = append(b, 0x85, 0x03, 0x00, 0xff, 0xff, 0x85, 0x01, 0x07)                               // an integer with a leading zero: a length of 65535
	b = append(b, 0x03, 0x00, 0x01, 0x2c, 0x06, 0xe0, 0, 0, 0, 1, 0, 0xc1, 0x02)                // a length of 300 and what reads as the header of a connection request
	b = append(b, 0x03, 0x00, 0x00, 0x05, 0x09)                                                 // a length below the smallest frame
	b = append(b, 0x89, 0x02, 0x03, 0x00)                                                       // 3, 0 just before the next frame
	return b
}

// TestFramingAfterLoss: where the framing of a direction is lost (bytes of
// the stream are missing, bytes that are no frame, a stream captured from
// its middle), every frame that follows is found, also when the bytes in
// between hold what looks like TPKT headers with lengths that reach over
// the following frames. Those bytes are counted one by one.
func TestFramingAfterLoss(t *testing.T) {
	const n = 10
	report := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: informationReport(t)}))
	setup := readExchange(t).setup
	rest := restOfPDU()
	cases := []struct {
		name      string
		handshake bool // the capture holds the start of the connection
		lose      bool // the segment before the rest is not captured
		split     int  // bytes per segment of the rest and the reports; 0: one segment each
	}{
		{"after a gap", true, true, 0},
		{"after a gap, in segments of 7 bytes", true, true, 7},
		{"after a gap, in segments of 1 byte", true, true, 1},
		{"after a gap, in one segment", true, true, 1 << 16},
		{"after bytes that are no frame", true, false, 0},
		{"after bytes that are no frame, in segments of 5 bytes", true, false, 5},
		{"at the start of a stream captured from its middle", false, false, 0},
		{"at the start of a stream captured from its middle, in segments of 3 bytes", false, false, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapture(t)
			if tc.handshake {
				c.handshake()
				c.units(setup, false)
			}
			if tc.lose {
				c.seq[1] += 200 // the start of a PDU of the server, not captured
			}
			stream := bytes.Clone(rest)
			for range n {
				stream = append(stream, report...)
			}
			if tc.split == 0 {
				c.tcp(1, 0x18, rest)
				for range n {
					c.tcp(1, 0x18, report)
				}
			} else {
				for part := range slices.Chunk(stream, tc.split) {
					c.tcp(1, 0x18, part)
				}
			}
			c.close()
			res := analyze(t, c.bytes(t))
			cn := res.Counters
			if len(res.Reports) != n || cn.TPKTResync != uint64(len(rest)) || cn.COTPErrors != 0 || cn.TSDUErrors != 0 {
				t.Errorf("%d reports of %d, %d bytes skipped of %d, %d COTP errors, %d TSDU errors", len(res.Reports), n, cn.TPKTResync, len(rest), cn.COTPErrors, cn.TSDUErrors)
			}
			wantGaps := 0
			if tc.lose {
				wantGaps = 1
			}
			if len(res.Associations) != 1 || res.Associations[0].Gaps != wantGaps || res.Associations[0].Reports != n {
				t.Errorf("%d associations; the first has %d gaps and %d reports, want %d and %d", len(res.Associations), res.Associations[0].Gaps,
					res.Associations[0].Reports, wantGaps, n)
			}
		})
	}
}

// TestFramingInSync: a direction that is synchronised takes a frame at its
// length. A frame whose TPDU does not decode is one COTP error and is
// passed over as a whole; the frames after it are found without a byte
// skipped.
func TestFramingInSync(t *testing.T) {
	report := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: informationReport(t)}))
	c := newCapture(t)
	c.handshake()
	c.units(readExchange(t).setup, false)
	c.tcp(1, 0x18, report)
	c.tcp(1, 0x18, tpkt(append([]byte{0x02, 0xff, 0x80}, restOfPDU()...))) // a frame, and no TPDU in it
	c.tcp(1, 0x18, report)
	c.close()
	res := analyze(t, c.bytes(t))
	if cn := res.Counters; len(res.Reports) != 2 || cn.COTPErrors != 1 || cn.TPKTResync != 0 {
		t.Errorf("%d reports, counters %+v", len(res.Reports), cn)
	}
}

// probe is the analyzer with a note, for every packet that delivered
// bytes, of the PDUs that have bytes in it: those its bytes completed, and
// one more when it left a frame or a TSDU incomplete.
type probe struct {
	*analyzer
	carried map[uint64]int
}

func pduCount(res *Result) int {
	n := len(res.Reports)
	for _, tr := range res.Transactions {
		if tr.Request != nil {
			n++
		}
		if tr.Response != nil {
			n++
		}
	}
	return n
}

func (p *probe) Data(c *flow.Conn, dir int, pos uint64, b []byte, ch flow.Chunk) {
	before := pduCount(p.res)
	p.analyzer.Data(c, dir, pos, b, ch)
	n := pduCount(p.res) - before
	if d := &c.User.(*conn).dirs[dir]; len(d.buf) > 0 || len(d.tsdu) > 0 || d.tsduOver {
		n++
	}
	p.carried[ch.Frame] += n
}

type packetRecord struct {
	ns      int64
	origLen uint32
	data    []byte
}

// packetsOf reads the packets of a capture that are of the link type of
// its first one.
func packetsOf(t *testing.T, file []byte) (uint16, []packetRecord) {
	t.Helper()
	rd, err := pcapio.NewReader(bytes.NewReader(file), pcapio.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out []packetRecord
	var lt uint16
	var p pcapio.Packet
	for {
		if err := rd.Next(&p); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			return lt, out
		}
		if len(out) == 0 {
			lt = p.LinkType
		}
		if p.LinkType == lt {
			out = append(out, packetRecord{p.TimeNS, p.OrigLen, bytes.Clone(p.Data)})
		}
	}
}

// pcapWithout writes the packets as a pcap file with nanosecond times,
// without the one at index skip (-1: all of them). It is called once per
// packet left out, so it writes into one buffer of the file's size.
func pcapWithout(lt uint16, pkts []packetRecord, skip int) []byte {
	size := 24
	for _, p := range pkts {
		size += 16 + len(p.data)
	}
	le := binary.LittleEndian
	b := make([]byte, 0, size)
	b = le.AppendUint32(b, 0xa1b23c4d)
	b = le.AppendUint16(le.AppendUint16(b, 2), 4)
	b = le.AppendUint32(le.AppendUint32(le.AppendUint32(le.AppendUint32(b, 0), 0), 262144), uint32(lt))
	for i, p := range pkts {
		if i == skip {
			continue
		}
		b = le.AppendUint32(le.AppendUint32(b, uint32(p.ns/1e9)), uint32(p.ns%1e9))
		b = le.AppendUint32(le.AppendUint32(b, uint32(len(p.data))), p.origLen)
		b = append(b, p.data...)
	}
	return b
}

// carriedPDUs runs the pipeline of Analyze over a capture with the probe.
func carriedPDUs(t *testing.T, file []byte, ports []uint16) map[uint64]int {
	t.Helper()
	rd, err := pcapio.NewReader(bytes.NewReader(file), pcapio.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := &probe{newAnalyzer(Options{Ports: ports, MaxAssembly: DefaultMaxAssembly}), map[uint64]int{}}
	dec := link.NewDecoder(1 << 20)
	tr := flow.NewTracker(flow.DefaultLimits, p)
	var pkt pcapio.Packet
	var seg link.Segment
	for rd.Next(&pkt) == nil {
		if et, ok := etherType(pkt.Data); pkt.LinkType == link.LinkEthernet && ok && (et == EtherTypeGOOSE || et == EtherTypeSV) {
			continue
		}
		if dec.Decode(pkt.LinkType, pkt.Data, &seg) != link.OK {
			continue
		}
		if slices.Contains(ports, seg.Src.Port()) || slices.Contains(ports, seg.Dst.Port()) {
			tr.Packet(&pkt, &seg)
		}
	}
	tr.Finish()
	return p.carried
}

// lossSensitive are packets of the public captures after which the rest
// of a PDU holds octets that read as a TPKT header with a length reaching
// over many later frames. TestOnePacketLoss always leaves them out.
var lossSensitive = map[string][]uint64{
	"ics-pcaps/Substation/ABB1.pcap":    {1442, 1655},
	"ics-pcaps/Substation/ABB2.pcap":    {1439, 1652},
	"ics-pcaps/Substation/ABB3.pcap":    {1845, 2112},
	"ics-pcaps/Substation/circuit.pcap": {1438, 1653},
	"ics-pcaps/mms1.pcap":               {86, 235},
	"ics-pcaps/mms2.pcap":               {1647, 1649},
	"ics-pcaps/mmsy.pcap":               {154, 426},
	"ics-pcaps/mmsy1.pcap":              {149, 421},
}

// TestOnePacketLoss: in the committed captures of other implementations,
// leaving out one packet that carries bytes of an MMS connection never
// loses more PDUs than have bytes in that packet. Of every capture the
// packets of lossSensitive and a few others are left out in turn (the one
// in the middle, and 8 evenly spread of a capture up to 512 KiB); with
// MMSTRACE_ALL_PACKETS=1 (the nightly run) every packet is.
func TestOnePacketLoss(t *testing.T) {
	every := os.Getenv("MMSTRACE_ALL_PACKETS") == "1"
	type entry struct {
		dir, file string
		ports     []uint16
	}
	var files []entry
	for _, set := range []entry{{dir: "public", ports: []uint16{102}}, {dir: "interop", ports: []uint16{1102}}} {
		dir, ports := set.dir, set.ports
		raw, err := os.ReadFile(filepath.Join("..", "testdata", "captures", dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Files []struct{ File string } `json:"files"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for _, f := range m.Files {
			files = append(files, entry{dir, f.File, ports})
		}
	}
	if len(files) < 80 {
		t.Fatalf("%d captures in the manifests", len(files))
	}
	tried, withPDUs := 0, 0
	for _, f := range files {
		file, err := os.ReadFile(filepath.Join("..", "testdata", "captures", f.dir, f.file))
		if err != nil {
			t.Fatal(err)
		}
		lt, pkts := packetsOf(t, file)
		whole := pcapWithout(lt, pkts, -1)
		res, err := Analyze(context.Background(), bytes.NewReader(whole), Options{Ports: f.ports})
		if err != nil {
			t.Fatalf("%s: %v", f.file, err)
		}
		base := pduCount(res)
		if base == 0 {
			continue
		}
		withPDUs++
		carried := carriedPDUs(t, whole, f.ports)
		frames := slices.Sorted(maps.Keys(carried))
		if !every && len(frames) > 8 {
			some := []uint64{frames[len(frames)/2]}
			if len(file) <= 512<<10 {
				for i := range 8 {
					some = append(some, frames[i*(len(frames)-1)/7])
				}
			}
			for _, fr := range lossSensitive[f.file] {
				if _, ok := carried[fr]; !ok {
					t.Errorf("%s: packet %d delivers no bytes of an MMS connection", f.file, fr)
				}
				some = append(some, fr)
			}
			slices.Sort(some)
			frames = slices.Compact(some)
		}
		for _, fr := range frames {
			res, err := Analyze(context.Background(), bytes.NewReader(pcapWithout(lt, pkts, int(fr-1))), Options{Ports: f.ports})
			if err != nil {
				t.Fatalf("%s without packet %d: %v", f.file, fr, err)
			}
			tried++
			if lost := base - pduCount(res); lost > carried[fr] {
				t.Errorf("%s: without packet %d, %d of %d PDUs are lost; %d have bytes in it (COTP errors %d, bytes skipped %d)", f.file, fr, lost, base,
					carried[fr], res.Counters.COTPErrors, res.Counters.TPKTResync)
			}
		}
	}
	if withPDUs < 60 || tried < 400 {
		t.Errorf("%d packets left out in %d captures with MMS PDUs: the captures do not exercise the framing", tried, withPDUs)
	}
}
