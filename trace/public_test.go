// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// publicSummary is what TestPublicCaptures holds a public capture to.
type publicSummary struct {
	Packets      uint64         `json:"packets"`
	Associations map[string]int `json:"associations"` // "open/close"
	Statuses     map[string]int `json:"statuses"`
	Services     map[string]int `json:"services"`
	Reports      int            `json:"reports"`
	DecodeErrors int            `json:"decode_errors"`
	GOOSE        []string       `json:"goose"` // "gocbRef: messages, issues"
	SV           []string       `json:"sv"`
	Counters     map[string]any `json:"counters"`
}

func summarize(r *Result) publicSummary {
	s := publicSummary{Packets: r.File.Packets, Associations: map[string]int{}, Statuses: map[string]int{}, Services: map[string]int{},
		Reports: len(r.Reports), GOOSE: []string{}, SV: []string{}}
	for _, a := range r.Associations {
		s.Associations[a.Open+"/"+a.Close]++
	}
	for _, t := range r.Transactions {
		s.Statuses[t.Status]++
		s.Services[t.Service]++
		if t.Request != nil && t.Request.DecodeError != "" {
			s.DecodeErrors++
		}
		if t.Response != nil && t.Response.DecodeError != "" {
			s.DecodeErrors++
		}
	}
	for _, p := range r.Reports {
		if p.PDU.DecodeError != "" {
			s.DecodeErrors++
		}
	}
	for _, g := range r.GOOSE {
		s.GOOSE = append(s.GOOSE, fmt.Sprintf("%s: %d messages, %d changes, issues %v", g.GocbRef, g.Messages, g.Changes, g.Issues))
	}
	for _, v := range r.SV {
		s.SV = append(s.SV, fmt.Sprintf("%s: %d ASDUs, %d lost, %d repeated", v.SvID, v.ASDUs, v.Lost, v.Repeated))
	}
	sort.Strings(s.GOOSE)
	sort.Strings(s.SV)
	c := r.Counters
	s.Counters = map[string]any{"unsupported": c.Unsupported, "tpkt_resync": c.TPKTResync, "cotp_errors": c.COTPErrors,
		"tsdu_errors": c.TSDUErrors, "bare_mms": c.BareMMS, "tso_segments": c.TSOSegments, "goose_errors": c.GOOSEErrors, "sv_errors": c.SVErrors}
	return s
}

// TestPublicCaptures holds every public capture (testdata/captures/public,
// manifest.json) to its recorded summary (expected.json): a change in
// what the library finds in them is a change to look at. Every MMS PDU of
// them also matches what Wireshark's dissector finds (make
// compare-wireshark). Regenerate expected.json with -update.
func TestPublicCaptures(t *testing.T) {
	dir := filepath.Join("..", "testdata", "captures", "public")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Files []struct{ File, SHA256 string } `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	got := map[string]publicSummary{}
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(dir, f.File))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s: checksum differs from the manifest", f.File)
		}
		r, err := Analyze(context.Background(), bytes.NewReader(b), Options{})
		if err != nil {
			t.Errorf("%s: %v", f.File, err)
			continue
		}
		got[f.File] = summarize(r)
	}
	gotJSON, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	exp := filepath.Join(dir, "expected.json")
	if *update {
		if err := os.WriteFile(exp, append(gotJSON, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(exp)
	if err != nil {
		t.Fatal(err)
	}
	var wantMap map[string]json.RawMessage
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatal(err)
	}
	for name, s := range got {
		g, _ := json.Marshal(s)
		var w any
		if err := json.Unmarshal(wantMap[name], &w); err != nil {
			t.Errorf("%s: not in expected.json", name)
			continue
		}
		wb, _ := json.Marshal(w)
		var gn any
		_ = json.Unmarshal(g, &gn)
		gb, _ := json.Marshal(gn)
		if !bytes.Equal(gb, wb) {
			t.Errorf("%s:\n got  %s\n want %s", name, gb, wb)
		}
	}
	if len(wantMap) != len(got) {
		t.Errorf("expected.json lists %d captures, the manifest %d", len(wantMap), len(got))
	}
}
