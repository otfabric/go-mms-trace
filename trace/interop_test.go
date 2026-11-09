// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInteropCaptures analyses the captures recorded between independent
// IEC 61850 stacks of otfabric/iec61850-interop (testdata/captures/interop,
// scripts/record-interop.sh): every frame decodes, every request is
// answered, and the associations, reports and streams are what the peers
// did.
func TestInteropCaptures(t *testing.T) {
	dir := filepath.Join("..", "testdata", "captures", "interop")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Files []struct {
			File, Kind, SHA256, Client string
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) < 10 {
		t.Fatalf("manifest lists %d files", len(m.Files))
	}
	for _, f := range m.Files {
		t.Run(f.File, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, f.File))
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != f.SHA256 {
				t.Fatalf("checksum differs from the manifest")
			}
			res, err := Analyze(context.Background(), strings.NewReader(string(b)), Options{Ports: []uint16{1102}})
			if err != nil {
				t.Fatal(err)
			}
			c := res.Counters
			if c.TPKTResync+c.COTPErrors+c.TSDUErrors+c.GOOSEErrors+c.SVErrors != 0 {
				t.Errorf("counters = %+v", c)
			}
			switch f.Kind {
			case "goose":
				if len(res.GOOSE) != 1 || res.GOOSE[0].Changes != 1 || len(res.GOOSE[0].Issues) != 0 {
					t.Errorf("GOOSE = %+v", res.GOOSE)
				}
				return
			case "sv":
				if len(res.SV) != 1 || res.SV[0].ASDUs < 1000 || res.SV[0].Lost != 0 || res.SV[0].Repeated != 0 {
					t.Errorf("SV = %+v", res.SV)
				}
				return
			}
			if len(res.Associations) == 0 || len(res.Transactions) == 0 {
				t.Fatalf("%d associations, %d transactions", len(res.Associations), len(res.Transactions))
			}
			for _, a := range res.Associations {
				if a.Open != "associate" || a.Accepted == nil || !*a.Accepted || a.Close == "" || a.Gaps != 0 || a.Initiate == nil {
					t.Errorf("association = %+v", a)
				}
			}
			for _, tr := range res.Transactions {
				if tr.Status != StatusOK && tr.Status != StatusError {
					t.Errorf("%s %d: %s", tr.Service, tr.InvokeID, tr.Status)
				}
				for _, p := range []*struct{ e string }{{tr.Request.DecodeError}, {tr.Response.DecodeError}} {
					if p.e != "" {
						t.Errorf("%s %d: %s", tr.Service, tr.InvokeID, p.e)
					}
				}
			}
			if strings.Contains(f.Client, "reporter") && len(res.Reports) != 1 {
				t.Errorf("reports = %d", len(res.Reports))
			}
		})
	}
}
