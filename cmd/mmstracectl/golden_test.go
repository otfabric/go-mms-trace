// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites the golden outputs: go test -run TestGolden -update.
var update = flag.Bool("update", false, "rewrite testdata/golden")

// The fixtures of the library's trace tests (go test ./trace -run
// TestFixture -update in the repository root rewrites them).
const (
	substation = "../../testdata/substation.pcap"
	damagedCap = "../../testdata/damaged.pcap"
)

// golden are the outputs compared byte for byte with testdata/golden.
var golden = map[string][]string{
	"info.txt":               {"info", substation},
	"info.json":              {"info", "--format", "json", substation},
	"associations.txt":       {"associations", substation},
	"associations.json":      {"associations", "--format", "json", substation},
	"transactions.txt":       {"transactions", substation},
	"transactions.json":      {"transactions", "--format", "json", substation},
	"transactions.csv":       {"transactions", "--format", "csv", substation},
	"transactions-error.txt": {"timeline", "--status", "error,orphan", "--service", "filedelete,read", substation},
	"reports.txt":            {"reports", substation},
	"reports.json":           {"reports", "--format", "json", substation},
	"reports.csv":            {"reports", "--format", "csv", substation},
	"goose.txt":              {"goose", substation},
	"goose.json":             {"goose", "--format", "json", substation},
	"goose.csv":              {"goose", "--format", "csv", substation},
	"sv.txt":                 {"sv", substation},
	"sv.json":                {"sv", "--format", "json", substation},
	"sv.csv":                 {"sv", "--format", "csv", substation},
	"damaged-info.txt":       {"info", damagedCap},
	"two-files.txt":          {"associations", substation, damagedCap},
}

func TestGolden(t *testing.T) {
	for name, args := range golden {
		var out, errw bytes.Buffer
		code := run(context.Background(), args, bytes.NewReader(nil), &out, &errw)
		want := exitOK
		if args[len(args)-1] == damagedCap {
			want = exitInvalidInput
		}
		if code != want {
			t.Errorf("%s: exit %d, want %d: %s", name, code, want, errw.String())
			continue
		}
		path := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (go test -run TestGolden -update)", err)
		}
		if !bytes.Equal(b, out.Bytes()) {
			t.Errorf("%s differs from %s:\n%s", name, path, out.String())
		}
	}
}
