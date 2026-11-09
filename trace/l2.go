// SPDX-License-Identifier: MIT

package trace

import (
	"fmt"

	"github.com/otfabric/go-iec61850/goose"
	"github.com/otfabric/go-iec61850/sv"
)

// EtherTypes of IEC 61850-8-1 GOOSE and IEC 61850-9-2 Sampled Values.
const (
	EtherTypeGOOSE = 0x88b8
	EtherTypeSV    = 0x88ba
)

// GooseStream is the GOOSE messages of one publisher: one source MAC,
// APPID and GoCB reference.
type GooseStream struct {
	Src      string // source MAC
	Dst      string // destination (multicast) MAC
	AppID    uint16
	VLAN     int // VLAN ID, -1 when untagged
	GocbRef  string
	DatSet   string
	GoID     string
	ConfRev  uint32
	Messages int
	// Changes counts state changes (stNum increments).
	Changes         int
	FirstNS, LastNS int64
	// Simulation and NdsCom count messages with these flags set.
	Simulation, NdsCom int
	// Issues count sequencing anomalies, by kind: "stNum decreased",
	// "stNum jumped" (by more than one), "sqNum gap", "repeated
	// (stNum, sqNum)", "confRev changed", "entries changed".
	Issues map[string]int
	// MaxPerSecond is the most messages in one second of capture time.
	MaxPerSecond int

	last      *goose.PDU
	seen      map[[2]uint32]bool
	perSecond map[int64]int
	entries   int
}

// SVStream is the Sampled Values of one publisher: one source MAC, APPID
// and svID.
type SVStream struct {
	Src      string
	Dst      string
	AppID    uint16
	VLAN     int
	SvID     string
	DatSet   string
	ConfRev  uint32
	Messages int
	// ASDUs counts samples; Lost counts smpCnt values skipped (not
	// counting the wrap), Repeated those seen twice in a row.
	ASDUs, Lost, Repeated int
	FirstNS, LastNS       int64
	// Wrap is the highest smpCnt seen plus one, an estimate of the
	// counter's wrap (the sample rate for a one-second wrap).
	Wrap int

	lastCnt int
}

func macString(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// goose adds a GOOSE frame.
func (a *analyzer) goose(frame []byte, ns int64) {
	f, err := goose.Decode(frame)
	if err != nil {
		a.res.Counters.GOOSEErrors++
		return
	}
	src := macString(f.Src)
	key := fmt.Sprintf("%s|%04x|%s", src, f.AppID, f.PDU.GocbRef)
	s := a.gooseByKey[key]
	if s == nil {
		vlan := -1
		if f.VLAN != nil {
			vlan = int(f.VLAN.ID)
		}
		s = &GooseStream{Src: src, Dst: macString(f.Dst), AppID: f.AppID, VLAN: vlan, GocbRef: f.PDU.GocbRef,
			Issues: map[string]int{}, seen: map[[2]uint32]bool{}, perSecond: map[int64]int{}, FirstNS: ns}
		a.gooseByKey[key] = s
		a.res.GOOSE = append(a.res.GOOSE, s)
	}
	p := f.PDU
	s.Messages++
	s.LastNS = ns
	s.DatSet, s.GoID = p.DatSet, p.GoID
	s.perSecond[ns/1e9]++
	if s.perSecond[ns/1e9] > s.MaxPerSecond {
		s.MaxPerSecond = s.perSecond[ns/1e9]
	}
	if f.Simulation || p.Test {
		s.Simulation++
	}
	if p.NdsCom {
		s.NdsCom++
	}
	pair := [2]uint32{p.StNum, p.SqNum}
	if s.seen[pair] {
		s.Issues["repeated (stNum, sqNum)"]++
	}
	s.seen[pair] = true
	if prev := s.last; prev != nil {
		switch {
		case p.StNum < prev.StNum:
			s.Issues["stNum decreased"]++
		case p.StNum > prev.StNum+1:
			s.Issues["stNum jumped"]++
			s.Changes++
		case p.StNum == prev.StNum+1:
			s.Changes++
		case p.SqNum != prev.SqNum+1 && p.SqNum > prev.SqNum:
			s.Issues["sqNum gap"]++
		}
		if p.ConfRev != prev.ConfRev {
			s.Issues["confRev changed"]++
		}
		if int(p.NumDatSetEntries) != s.entries {
			s.Issues["entries changed"]++
		}
	}
	s.ConfRev, s.entries = p.ConfRev, int(p.NumDatSetEntries)
	pc := p
	s.last = &pc
}

// sv adds a Sampled Values frame.
func (a *analyzer) sv(frame []byte, ns int64) {
	f, err := sv.Decode(frame)
	if err != nil {
		a.res.Counters.SVErrors++
		return
	}
	src := macString(f.Src)
	for _, asdu := range f.PDU.ASDUs {
		key := fmt.Sprintf("%s|%04x|%s", src, f.AppID, asdu.SvID)
		s := a.svByKey[key]
		if s == nil {
			vlan := -1
			if f.VLAN != nil {
				vlan = int(f.VLAN.ID)
			}
			s = &SVStream{Src: src, Dst: macString(f.Dst), AppID: f.AppID, VLAN: vlan, SvID: asdu.SvID, FirstNS: ns, lastCnt: -1}
			a.svByKey[key] = s
			a.res.SV = append(a.res.SV, s)
		}
		s.ASDUs++
		s.LastNS = ns
		s.DatSet, s.ConfRev = asdu.DatSet, asdu.ConfRev
		cnt := int(asdu.SmpCnt)
		if cnt+1 > s.Wrap {
			s.Wrap = cnt + 1
		}
		switch {
		case s.lastCnt < 0:
		case cnt == s.lastCnt:
			s.Repeated++
		case cnt > s.lastCnt+1:
			s.Lost += cnt - s.lastCnt - 1
		}
		s.lastCnt = cnt
	}
	if len(f.PDU.ASDUs) > 0 {
		key := fmt.Sprintf("%s|%04x|%s", src, f.AppID, f.PDU.ASDUs[0].SvID)
		a.svByKey[key].Messages++
	}
}
