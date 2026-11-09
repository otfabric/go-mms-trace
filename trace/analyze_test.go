// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-cotp"
	"github.com/otfabric/go-iec61850/goose"
	mms "github.com/otfabric/go-mms"
)

func hz() mms.ObjectName {
	return mms.ObjectName{Scope: mms.ObjectScopeDomain, Domain: "LD0", ItemID: "MMXU1$MX$Hz"}
}

func standardWork(t *testing.T) func(context.Context, *mms.Client) {
	return func(ctx context.Context, c *mms.Client) {
		t.Helper()
		if _, err := c.Identify(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ReadObject(ctx, hz()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.WriteObject(ctx, hz(), mms.NewInteger(51)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GetNameListAll(ctx, mms.NameListRequest{ObjectClass: mms.ObjectClassNamedVariable, Scope: mms.ObjectScopeDomain, DomainID: "LD0"}); err != nil {
			t.Fatal(err)
		}
		if err := c.FileDelete(ctx, "x"); err == nil {
			t.Fatal("FileDelete succeeded")
		}
		if err := c.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func analyze(t *testing.T, b []byte) *Result {
	t.Helper()
	res, err := Analyze(context.Background(), bytes.NewReader(b), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestAnalyzeAssociation: a real association, framed as a capture, gives
// one association with every transaction paired, plus the GOOSE and SV
// streams with their anomalies.
func TestAnalyzeAssociation(t *testing.T) {
	units := recordAssociation(t, standardWork(t))
	for _, split := range []bool{false, true} {
		c := newCapture(t)
		c.handshake()
		c.units(units, split)
		c.close()
		for i, p := range [][2]uint32{{1, 0}, {1, 1}, {1, 2}, {2, 0}, {2, 1}, {2, 1}, {5, 0}, {4, 0}} {
			_ = i
			c.goose(t, p[0], p[1])
		}
		for _, n := range []uint16{0, 1, 2, 5, 5, 6} {
			c.sv(t, n)
		}
		res := analyze(t, c.bytes(t))

		if res.File.Format != "pcap" || res.File.Packets == 0 || res.File.FirstNS == 0 {
			t.Errorf("file = %+v", res.File)
		}
		if len(res.Associations) != 1 {
			t.Fatalf("associations = %+v", res.Associations)
		}
		as := res.Associations[0]
		if as.Open != "associate" || as.Close != "conclude" || as.Accepted == nil || !*as.Accepted || as.Initiate == nil ||
			as.Server.Port() != 102 || as.Client.Port() != 40000 || as.Gaps != 0 || string(as.CalledTSAP) != "\x00\x01" || as.Authentication != "none" {
			t.Errorf("association = %+v", as)
		}
		byService := map[string]*Transaction{}
		for _, tr := range res.Transactions {
			byService[tr.Service] = tr
			if tr.LatencyNS() <= 0 {
				t.Errorf("%s latency %d", tr.Service, tr.LatencyNS())
			}
		}
		for svc, status := range map[string]string{"Identify": StatusOK, "Read": StatusOK, "Write": StatusOK, "GetNameList": StatusOK, "FileDelete": StatusError} {
			if tr := byService[svc]; tr == nil || tr.Status != status {
				t.Errorf("split=%v %s = %+v", split, svc, tr)
			}
		}
		if r := byService["Read"]; r != nil && (r.Request.Variables[0].Name != hz() || len(r.Response.Values) != 1) {
			t.Errorf("read = %+v / %+v", r.Request, r.Response)
		}
		if as.Transactions != len(res.Transactions) || as.Unanswered != 0 {
			t.Errorf("counts = %+v", as)
		}

		if len(res.GOOSE) != 1 {
			t.Fatalf("GOOSE = %+v", res.GOOSE)
		}
		g := res.GOOSE[0]
		want := map[string]int{"repeated (stNum, sqNum)": 1, "stNum jumped": 1, "stNum decreased": 1}
		for k, v := range want {
			if g.Issues[k] != v {
				t.Errorf("GOOSE issue %q = %d, want %d (%v)", k, g.Issues[k], v, g.Issues)
			}
		}
		if g.Messages != 8 || g.GocbRef != "IED1LD0/LLN0$GO$gcb1" || g.AppID != 1 || g.VLAN != -1 || g.Changes != 2 {
			t.Errorf("GOOSE = %+v", g)
		}
		if len(res.SV) != 1 || res.SV[0].Lost != 2 || res.SV[0].Repeated != 1 || res.SV[0].ASDUs != 6 || res.SV[0].SvID != "MU01" {
			t.Errorf("SV = %+v", res.SV)
		}
	}
}

// TestAnalyzeEdges: a capture that starts mid-association, loses a
// segment, ends before the responses, carries reports, and frames garbage.
func TestAnalyzeEdges(t *testing.T) {
	var reportUnits []unit
	units := recordAssociation(t, func(ctx context.Context, c *mms.Client) {
		for range 3 {
			if _, err := c.ReadObject(ctx, hz()); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
	// Requests and responses after the association: skip the AARQ/AARE
	// (midstream), lose the second response, keep the first request only
	// once and the third response without its request (orphan).
	var reqs, resps []unit
	for _, u := range units[2:] {
		if u.dir == mms.RawHookSend {
			reqs = append(reqs, u)
		} else {
			resps = append(resps, u)
		}
	}
	if len(reqs) < 3 || len(resps) < 3 {
		t.Fatalf("units: %d requests, %d responses", len(reqs), len(resps))
	}
	reportUnits = []unit{{mms.RawHookRecv, informationReport(t)}}

	c := newCapture(t)
	c.units(reqs[:2], false)                             // requests 1 and 2
	c.units(resps[:1], false)                            // response 1
	c.seq[1] += 50                                       // response 2 never captured: a gap
	c.units(resps[2:3], false)                           // response 3, its request missing
	c.units(reportUnits, false)                          // an InformationReport
	c.tcp(1, 0x18, []byte{0xde, 0xad, 0xbe, 0xef, 0x01}) // garbage, then resync
	c.units(reportUnits, false)
	c.tcp(0, 0x18, tpkt([]byte{0x02, 0xff, 0x80})) // a TPDU that does not decode
	c.tcp(0, 0x04, nil)                            // reset
	// Other TCP traffic (another port pair).
	c.otherTCP()
	res := analyze(t, c.bytes(t))

	if len(res.Associations) != 1 {
		t.Fatalf("associations = %+v", res.Associations)
	}
	as := res.Associations[0]
	if as.Open != "midstream" || as.Close != "reset" || as.Gaps != 1 || as.Reports != 2 || as.Accepted != nil {
		t.Errorf("association = %+v", as)
	}
	status := map[string]int{}
	for _, tr := range res.Transactions {
		status[tr.Status]++
	}
	if status[StatusOK] != 1 || status[StatusUnanswered] != 1 || status[StatusOrphan] != 1 {
		t.Errorf("statuses = %v", status)
	}
	if res.Counters.TPKTResync == 0 || res.Counters.COTPErrors != 1 || len(res.Reports) != 2 {
		t.Errorf("counters = %+v, reports %d", res.Counters, len(res.Reports))
	}
	if r := res.Reports[0]; len(r.PDU.Values) != 1 || r.Association != as.ID {
		t.Errorf("report = %+v", r.PDU)
	}
}

// informationReport is a session data unit carrying an InformationReport.
func informationReport(t *testing.T) []byte {
	t.Helper()
	var got []byte
	srvUnits := recordReport(t)
	for _, u := range srvUnits {
		if u.dir == mms.RawHookRecv {
			if p, err := mms.DecodeTSDU(u.data); err == nil && p.PDU != nil && p.PDU.Kind == "unconfirmed" {
				got = u.data
			}
		}
	}
	if got == nil {
		t.Fatal("no information report recorded")
	}
	return got
}

func TestAnalyzeDamaged(t *testing.T) {
	c := newCapture(t)
	c.goose(t, 1, 0)
	b := c.bytes(t)
	b = append(b, 0xff, 0xff, 0xff) // a record header cut short
	res, err := Analyze(context.Background(), bytes.NewReader(b), Options{})
	if err == nil && res != nil && res.File.Packets != 1 {
		t.Errorf("damaged = %+v, %v", res.File, err)
	}
	if res, err := Analyze(context.Background(), bytes.NewReader([]byte("not a capture")), Options{}); !errors.Is(err, ErrFormat) || res != nil {
		t.Errorf("not a capture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, bytes.NewReader(newCapture(t).bytes(t)), Options{}); err == nil {
		t.Error("a cancelled analysis succeeded")
	}
}

func TestAnalyzeStreamsAndStack(t *testing.T) {
	c := newCapture(t)
	// A VLAN-tagged stream with flags and changes.
	steps := []func(*goose.Frame){
		func(f *goose.Frame) { f.VLAN = &goose.VLAN{ID: 10, Priority: 4}; f.Simulation = true },
		func(f *goose.Frame) { f.VLAN = &goose.VLAN{ID: 10, Priority: 4}; f.PDU.SqNum = 3; f.PDU.NdsCom = true },
		func(f *goose.Frame) {
			f.VLAN = &goose.VLAN{ID: 10, Priority: 4}
			f.PDU.SqNum = 4
			f.PDU.ConfRev = 2
			f.PDU.AllData = append(f.PDU.AllData, mms.NewBoolean(false))
		},
	}
	for _, s := range steps {
		c.gooseFrame(t, s)
	}
	// Frames with the EtherTypes that do not decode.
	c.packet(append(append([]byte{1, 0x0c, 0xcd, 1, 0, 3, 2, 0, 0, 0, 0, 6}, 0x88, 0xb8), make([]byte, 10)...))
	c.packet(append(append([]byte{1, 0x0c, 0xcd, 4, 0, 3, 2, 0, 0, 0, 0, 6}, 0x88, 0xba), make([]byte, 10)...))
	c.packet([]byte{1, 2, 3}) // too short for an EtherType

	// An association that aborts, with a TSDU that is not MMS, a short
	// TPKT, a retransmission and an oversized TSDU.
	c.handshake()
	c.tcp(0, 0x18, []byte{3, 0, 0, 5, 0}) // TPKT length below 7
	c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: []byte{0x99, 0x00}})))
	save := c.seq[0]
	c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: []byte{0x99, 0x01}})))
	c.seq[0] = save // the same segment again
	c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: []byte{0x99, 0x01}})))
	maxTSDU = 8
	t.Cleanup(func() { maxTSDU = MaxTSDU })
	c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{UserData: make([]byte, 6)})))
	c.tcp(0, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: make([]byte, 6)})))
	c.tcp(1, 0x18, tpkt(marshal(t, &cotp.DT{EOT: true, UserData: []byte{0x19, 0x00}}))) // session abort
	c.close()

	// A second connection that ends with a COTP disconnect request.
	c.port, c.seq = 40002, [2]uint32{1, 1}
	c.handshake()
	c.tcp(1, 0x18, tpkt(marshal(t, &cotp.DR{DestinationRef: 1, SourceRef: 2})))
	c.close()

	res := analyze(t, c.bytes(t))
	g := res.GOOSE[0]
	if g.VLAN != 10 || g.Simulation != 1 || g.NdsCom != 1 || g.Issues["sqNum gap"] != 1 || g.Issues["confRev changed"] != 1 || g.Issues["entries changed"] != 1 {
		t.Errorf("GOOSE = %+v", g)
	}
	cn := res.Counters
	if cn.GOOSEErrors != 1 || cn.SVErrors != 1 || cn.TSDUErrors < 3 || cn.TPKTResync == 0 {
		t.Errorf("counters = %+v", cn)
	}
	if len(res.Associations) != 2 || res.Associations[0].Close != "abort" || res.Associations[1].Close != "disconnect" || res.Associations[1].Open != "connect" {
		for _, a := range res.Associations {
			t.Errorf("association = %+v", a)
		}
	}
	if (&Transaction{}).LatencyNS() != -1 {
		t.Error("latency without times")
	}
}

// TestAnalyzeTraceEnds: a request still waiting when the capture ends is
// pending, not unanswered; a TCP connection without the ISO stack is no
// association.
func TestAnalyzeTraceEnds(t *testing.T) {
	units := recordAssociation(t, func(ctx context.Context, c *mms.Client) {
		if _, err := c.ReadObject(ctx, hz()); err != nil {
			t.Fatal(err)
		}
		_ = c.Abort(ctx)
	})
	c := newCapture(t)
	c.handshake()
	for _, u := range units {
		c.units([]unit{u}, false)
		if u.dir == mms.RawHookSend {
			if p, _ := mms.DecodeTSDU(u.data); p != nil && p.PDU != nil && p.PDU.Kind == "confirmed-request" {
				break
			}
		}
	}
	c.port, c.seq = 40005, [2]uint32{1, 1}
	c.tcp(0, 0x02, nil) // a SYN only
	c.tcp(1, 0x14, nil) // refused
	res := analyze(t, c.bytes(t))
	if len(res.Associations) != 1 || res.Associations[0].Close != "" {
		t.Fatalf("associations = %+v", res.Associations)
	}
	last := res.Transactions[len(res.Transactions)-1]
	if last.Status != StatusPending || res.Associations[0].Unanswered != 0 {
		t.Errorf("last = %+v", last)
	}
	(&analyzer{}).Repeat(nil, 0, 0, 0)
}
