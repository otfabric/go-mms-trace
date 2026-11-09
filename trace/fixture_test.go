// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	mms "github.com/otfabric/go-mms"
)

// update rewrites the committed fixtures: go test ./trace -run TestFixture -update.
var update = flag.Bool("update", false, "rewrite the fixtures in ../testdata")

// Fixture files at the repository root, read by these tests and by the
// golden tests of cmd/mmstracectl.
var (
	fixtureFile = filepath.Join("..", "testdata", "substation.pcap")
	damagedFile = filepath.Join("..", "testdata", "damaged.pcap")
)

// buildFixture builds the substation capture from real go-mms
// associations: a complete one (Identify, Read, Write, GetNameList, a
// failing FileDelete, Conclude), one that receives an InformationReport and
// aborts, one captured midstream with a lost response, an orphan response
// and a reset, one that is still waiting when the capture ends, and GOOSE
// and Sampled Values streams with sequencing anomalies.
func buildFixture(t *testing.T) []byte {
	t.Helper()
	full := recordAssociation(t, standardWork(t))
	reads := recordAssociation(t, func(ctx context.Context, c *mms.Client) {
		for range 3 {
			if _, err := c.ReadObject(ctx, hz()); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
	report := recordReport(t)

	c := newCapture(t)
	c.goose(t, 1, 0)
	c.sv(t, 0)
	c.sv(t, 1)

	// 1: the complete association.
	c.handshake()
	c.units(full, false)
	c.close()
	c.goose(t, 1, 1)
	c.goose(t, 2, 0)

	// 2: a report, then an abort.
	c.port, c.seq = 40001, [2]uint32{1, 1}
	c.handshake()
	c.units(report, true)
	c.tcp(0, 0x11, nil)
	c.tcp(1, 0x11, nil)
	c.sv(t, 2)
	c.sv(t, 5)
	c.sv(t, 5)

	// 3: midstream; the second response is lost, the third request was
	// not captured, then a reset.
	var reqs, resps []unit
	for _, u := range reads[2:] {
		if u.dir == mms.RawHookSend {
			reqs = append(reqs, u)
		} else {
			resps = append(resps, u)
		}
	}
	if len(reqs) < 3 || len(resps) < 3 {
		t.Fatalf("units: %d requests, %d responses", len(reqs), len(resps))
	}
	c.port, c.seq = 40002, [2]uint32{1, 1}
	c.units(reqs[:1], false)
	c.units(resps[:1], false)
	c.units(reqs[1:2], false)
	c.seq[1] += 64 // the second response is not captured: a gap
	c.units(resps[2:3], false)
	c.tcp(0, 0x04, nil)
	c.goose(t, 2, 1)
	c.goose(t, 2, 1)
	c.goose(t, 4, 0)

	// 4: associated, one request, no answer before the capture ends.
	c.port, c.seq = 40003, [2]uint32{1, 1}
	c.handshake()
	c.units(reads[:2], false)
	c.units(reqs[:1], false)
	c.otherTCP()
	return c.bytes(t)
}

// TestFixture checks the committed fixtures against what the generator
// builds now (-update rewrites them) and what Analyze finds in them.
func TestFixture(t *testing.T) {
	if *update {
		b := buildFixture(t)
		if err := os.MkdirAll(filepath.Dir(fixtureFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixtureFile, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(damagedFile, damage(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("%v (go test ./trace -run TestFixture -update)", err)
	}
	res := analyze(t, b)
	if len(res.Associations) != 4 {
		t.Fatalf("associations = %d", len(res.Associations))
	}
	closes := []string{"conclude", "abort", "reset", ""}
	for i, as := range res.Associations {
		if as.Close != closes[i] {
			t.Errorf("association %d close = %q, want %q", as.ID, as.Close, closes[i])
		}
	}
	status := map[string]int{}
	for _, tr := range res.Transactions {
		status[tr.Status]++
	}
	for _, s := range []string{StatusOK, StatusError, StatusUnanswered, StatusOrphan, StatusPending} {
		if status[s] == 0 {
			t.Errorf("no %s transaction: %v", s, status)
		}
	}
	if len(res.Reports) != 1 || len(res.GOOSE) != 1 || len(res.SV) != 1 || res.Associations[2].Gaps != 1 {
		t.Errorf("reports %d, GOOSE %d, SV %d, gaps %d", len(res.Reports), len(res.GOOSE), len(res.SV), res.Associations[2].Gaps)
	}

	d, err := os.ReadFile(damagedFile)
	if err != nil {
		t.Fatal(err)
	}
	res, err = Analyze(context.Background(), bytes.NewReader(d), Options{})
	if !errors.Is(err, ErrCorrupt) || res == nil || res.File.Packets == 0 {
		t.Errorf("damaged: %v, %+v", err, res)
	}
	// Cut short: what was read, the tail flagged, no error.
	res = analyze(t, b[:len(b)-5])
	if !res.File.TruncatedTail || res.File.InputBytes != int64(len(b)-5) || len(res.File.Links) != 1 || res.File.Links[0] != "ethernet" {
		t.Errorf("cut short: %+v", res.File)
	}
}

// damage gives the record after the first ten an impossible captured
// length, so reading stops there with ErrCorrupt.
func damage(b []byte) []byte {
	d := bytes.Clone(b)
	off := 24 // pcap file header
	for range 10 {
		off += 16 + int(binary.LittleEndian.Uint32(d[off+8:]))
	}
	binary.LittleEndian.PutUint32(d[off+8:], 0x7fffffff)
	return d
}
