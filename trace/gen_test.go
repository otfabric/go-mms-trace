// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-cotp"
	"github.com/otfabric/go-iec61850/goose"
	"github.com/otfabric/go-iec61850/sv"
	mms "github.com/otfabric/go-mms"
	"github.com/otfabric/go-mms/transport/iso"

	"github.com/otfabric/go-mms-trace/internal/pcapio"
)

// unit is one ISO upper-layer unit of a real association, as the client
// sent ("send") or received ("recv") it.
type unit struct {
	dir  string
	data []byte
}

// recordAssociation runs a real go-mms client against a go-mms server
// over TCP and records every unit the client sent and received.
func recordAssociation(t *testing.T, work func(context.Context, *mms.Client)) []unit {
	t.Helper()
	srv := mms.NewServer(mms.ServerOptions{})
	srv.HandleIdentify(func(context.Context, mms.IdentifyRequest) (*mms.ServerIdentity, error) {
		return &mms.ServerIdentity{Vendor: "OT Fabric", Model: "trace", Revision: "1"}, nil
	})
	if err := srv.RegisterDomain("LD0"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{"MMXU1$MX$Hz", "GGIO1$ST$Ind1"} {
		if err := srv.RegisterVariable(mms.Variable{
			Name:     mms.ObjectName{Scope: mms.ObjectScopeDomain, Domain: "LD0", ItemID: mms.ItemID(item)},
			TypeSpec: mms.TypeSpec{Type: mms.ValueTypeInteger, Size: 32},
			Read:     func(context.Context) (*mms.Value, error) { return mms.NewInteger(50), nil },
			Write:    func(context.Context, *mms.Value) error { return nil },
		}); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := iso.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx, ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	var mu sync.Mutex
	var units []unit
	c, err := iso.Dial(ctx, ln.Addr().String(), iso.WithClientDialOptions(mms.DialOptions{RawHook: func(dir string, raw []byte) {
		mu.Lock()
		defer mu.Unlock()
		units = append(units, unit{dir, bytes.Clone(raw)})
	}}))
	if err != nil {
		t.Fatal(err)
	}
	work(ctx, c)
	mu.Lock()
	defer mu.Unlock()
	return append([]unit(nil), units...)
}

// capture builds a pcap file.
type capture struct {
	t    *testing.T
	buf  bytes.Buffer
	w    *pcapio.PcapWriter
	ns   int64
	seq  [2]uint32 // client, server
	port uint16
}

var (
	clientMAC = []byte{0x02, 0, 0, 0, 0, 1}
	serverMAC = []byte{0x02, 0, 0, 0, 0, 2}
	clientIP  = []byte{10, 0, 0, 1}
	serverIP  = []byte{10, 0, 0, 2}
)

func newCapture(t *testing.T) *capture {
	t.Helper()
	c := &capture{t: t, ns: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).UnixNano(), seq: [2]uint32{1000, 5000}, port: 40000}
	w, err := pcapio.NewPcapWriter(&c.buf, pcapio.PcapOptions{LinkType: 1, Nanos: true})
	if err != nil {
		t.Fatal(err)
	}
	c.w = w
	return c
}

func (c *capture) packet(data []byte) {
	c.t.Helper()
	c.ns += int64(time.Millisecond)
	if err := c.w.WritePacket(c.ns, 0, data); err != nil {
		c.t.Fatal(err)
	}
}

// tcp writes a TCP segment from the client (from=0) or the server.
func (c *capture) tcp(from int, flags byte, payload []byte) {
	srcMAC, dstMAC, srcIP, dstIP := clientMAC, serverMAC, clientIP, serverIP
	sport, dport := c.port, uint16(102)
	if from == 1 {
		srcMAC, dstMAC, srcIP, dstIP = serverMAC, clientMAC, serverIP, clientIP
		sport, dport = 102, c.port
	}
	b := append([]byte{}, dstMAC...)
	b = append(b, srcMAC...)
	b = append(b, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(payload)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:], srcIP)
	copy(ip[16:], dstIP)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], c.seq[from])
	binary.BigEndian.PutUint32(tcp[8:], c.seq[1-from])
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	b = append(b, ip...)
	b = append(b, tcp...)
	b = append(b, payload...)
	c.packet(b)
	c.seq[from] += uint32(len(payload))
	if flags&0x03 != 0 { // SYN or FIN take a sequence number
		c.seq[from]++
	}
}

// otherTCP writes a TCP segment between two ports that are not MMS.
func (c *capture) otherTCP() {
	b := append([]byte{}, serverMAC...)
	b = append(b, clientMAC...)
	b = append(b, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[8], ip[9] = 64, 6
	copy(ip[12:], clientIP)
	copy(ip[16:], serverIP)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 50000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	c.packet(append(append(b, ip...), tcp...))
}

func tpkt(tpdu []byte) []byte {
	b := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(tpdu)))
	return append(b, tpdu...)
}

func marshal(t *testing.T, m interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// handshake writes the TCP and COTP connection setup.
func (c *capture) handshake() {
	c.tcp(0, 0x02, nil)
	c.tcp(1, 0x12, nil)
	c.tcp(0, 0x10, nil)
	c.tcp(0, 0x18, tpkt(marshal(c.t, &cotp.CR{SourceRef: 1, CallingSelector: []byte{0, 1}, CalledSelector: []byte{0, 1}})))
	c.tcp(1, 0x18, tpkt(marshal(c.t, &cotp.CC{DestinationRef: 1, SourceRef: 2})))
}

// units writes recorded units as COTP data, one DT each (split in two
// when split is set), from the client for "send".
func (c *capture) units(us []unit, split bool) {
	for _, u := range us {
		from := 1
		if u.dir == mms.RawHookSend {
			from = 0
		}
		if split && len(u.data) > 8 {
			h := len(u.data) / 2
			c.tcp(from, 0x18, tpkt(marshal(c.t, &cotp.DT{UserData: u.data[:h]})))
			c.tcp(from, 0x18, tpkt(marshal(c.t, &cotp.DT{EOT: true, UserData: u.data[h:]})))
			continue
		}
		c.tcp(from, 0x18, tpkt(marshal(c.t, &cotp.DT{EOT: true, UserData: u.data})))
	}
}

func (c *capture) close() {
	c.tcp(0, 0x11, nil)
	c.tcp(1, 0x11, nil)
}

func (c *capture) goose(t *testing.T, stNum, sqNum uint32) {
	t.Helper()
	b, err := goose.Encode(&goose.Frame{Dst: goose.MAC{0x01, 0x0c, 0xcd, 0x01, 0, 1}, Src: goose.MAC{0x02, 0, 0, 0, 0, 9}, AppID: 1,
		PDU: goose.PDU{GocbRef: "IED1LD0/LLN0$GO$gcb1", TimeAllowedToLive: 2000, DatSet: "IED1LD0/LLN0$ds1", GoID: "gcb1",
			StNum: stNum, SqNum: sqNum, ConfRev: 1, AllData: []*mms.Value{mms.NewBoolean(true)}}})
	if err != nil {
		t.Fatal(err)
	}
	c.packet(b)
}

// gooseFrame writes a GOOSE frame built from f's defaults with changes.
func (c *capture) gooseFrame(t *testing.T, change func(*goose.Frame)) {
	t.Helper()
	f := &goose.Frame{Dst: goose.MAC{0x01, 0x0c, 0xcd, 0x01, 0, 2}, Src: goose.MAC{0x02, 0, 0, 0, 0, 7}, AppID: 2,
		PDU: goose.PDU{GocbRef: "IED2LD0/LLN0$GO$gcb2", TimeAllowedToLive: 2000, DatSet: "IED2LD0/LLN0$ds", StNum: 1, ConfRev: 1,
			AllData: []*mms.Value{mms.NewBoolean(true)}}}
	change(f)
	b, err := goose.Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	c.packet(b)
}

func (c *capture) sv(t *testing.T, smpCnt uint16) {
	t.Helper()
	b, err := sv.Encode(&sv.Frame{Dst: sv.MAC{0x01, 0x0c, 0xcd, 0x04, 0, 1}, Src: sv.MAC{0x02, 0, 0, 0, 0, 8}, AppID: 0x4000,
		PDU: sv.PDU{ASDUs: []sv.ASDU{{SvID: "MU01", SmpCnt: smpCnt, ConfRev: 1, Sample: make([]byte, 64)}}}})
	if err != nil {
		t.Fatal(err)
	}
	c.packet(b)
}

func (c *capture) bytes(t *testing.T) []byte {
	t.Helper()
	if err := c.w.Flush(); err != nil {
		t.Fatal(err)
	}
	return c.buf.Bytes()
}

// recordReport records a client receiving one InformationReport.
func recordReport(t *testing.T) []unit {
	t.Helper()
	srv := mms.NewServer(mms.ServerOptions{})
	if err := srv.RegisterDomain("LD0"); err != nil {
		t.Fatal(err)
	}
	ln, err := iso.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx, ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()
	var mu sync.Mutex
	var units []unit
	got := make(chan struct{}, 1)
	c, err := iso.Dial(ctx, ln.Addr().String(), iso.WithClientDialOptions(mms.DialOptions{RawHook: func(dir string, raw []byte) {
		mu.Lock()
		defer mu.Unlock()
		units = append(units, unit{dir, bytes.Clone(raw)})
	}}))
	if err != nil {
		t.Fatal(err)
	}
	c.OnInformationReport(func(*mms.InformationReportIndication) { got <- struct{}{} })
	// Dial returns when the client has the AARE; the server registers the
	// connection after sending it. A broadcast before that reaches nobody.
	for len(srv.Connections()) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("the server never registered the association")
		case <-time.After(5 * time.Millisecond):
		}
	}
	name := mms.ObjectName{Scope: mms.ObjectScopeDomain, Domain: "LD0", ItemID: "LLN0$RP$urcb"}
	if err := srv.Broadcast(ctx, &mms.InformationReportRequest{Variables: []mms.ObjectName{name}, Values: []*mms.Value{mms.NewInteger(1)}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-ctx.Done():
		t.Fatal("no report")
	}
	_ = c.Abort(ctx)
	mu.Lock()
	defer mu.Unlock()
	return append([]unit(nil), units...)
}
