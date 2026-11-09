// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-mms-trace/trace"
)

func cli(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(context.Background(), args, bytes.NewReader(stdin), &out, &errw)
	return code, out.String(), errw.String()
}

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(substation)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExitCodes(t *testing.T) {
	dir := t.TempDir()
	notCapture := filepath.Join(dir, "x.pcap")
	if err := os.WriteFile(notCapture, []byte("not a capture file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"nope"}, exitUsage},
		{[]string{"info"}, exitUsage},
		{[]string{"info", "--nope", substation}, exitUsage},
		{[]string{"info", "--format", "csv", substation}, exitUsage},
		{[]string{"version", "extra"}, exitUsage},
		{[]string{"version", "--format", "csv"}, exitUsage},
		{[]string{"transactions", "--status", "bad", substation}, exitUsage},
		{[]string{"transactions", "--assoc", "0", substation}, exitUsage},
		{[]string{"transactions", "--assoc", "x", substation}, exitUsage},
		{[]string{"goose", "--port", "0", substation}, exitUsage},
		{[]string{"sv", "--port", "70000", substation}, exitUsage},
		{[]string{"sv", "--port", "", substation}, exitUsage},
		{[]string{"reports", "--max-packet", "-1", substation}, exitUsage},
		{[]string{"info", "-", substation}, exitUsage},
		{[]string{"info", filepath.Join(dir, "missing.pcap")}, exitInvalidInput},
		{[]string{"info", notCapture}, exitInvalidInput},
		{[]string{"info", substation, damagedCap}, exitInvalidInput},
		{[]string{"info", "--port", "102,3782", "--max-packet", "65536", substation}, exitOK},
	}
	for _, tc := range cases {
		code, out, errs := cli(t, nil, tc.args...)
		if code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s)", tc.args, code, tc.code, errs)
		}
		if code == exitUsage && !strings.Contains(errs, "mmstracectl --help") {
			t.Errorf("%v: usage error without the help hint: %q", tc.args, errs)
		}
		if code == exitInvalidInput && tc.args[len(tc.args)-1] != damagedCap && out != "" {
			t.Errorf("%v: output before an input error: %q", tc.args, out)
		}
	}
}

func TestStdin(t *testing.T) {
	code, out, errs := cli(t, readFixture(t), "associations", "--format", "json", "-")
	if code != exitOK {
		t.Fatalf("exit %d %s", code, errs)
	}
	var doc document[associationsJSON]
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || len(doc.Files) != 1 || doc.Files[0].File != "-" || len(doc.Files[0].Associations) != 4 {
		t.Errorf("document = %+v", doc)
	}
}

// TestCLIEqualsLibrary: the transactions the CLI lists are the library's.
func TestCLIEqualsLibrary(t *testing.T) {
	res, err := trace.Analyze(context.Background(), bytes.NewReader(readFixture(t)), trace.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := cli(t, nil, "transactions", "--format", "csv", substation)
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if code != exitOK || err != nil {
		t.Fatalf("exit %d, %v", code, err)
	}
	if len(rows) != len(res.Transactions)+1 {
		t.Errorf("%d rows for %d transactions", len(rows)-1, len(res.Transactions))
	}
}

func TestFilters(t *testing.T) {
	cases := []struct {
		args []string
		rows int
	}{
		{[]string{"--service", "READ"}, 5},
		{[]string{"--status", "ok"}, 5},
		{[]string{"--assoc", "3,4"}, 4},
		{[]string{"--assoc", "1", "--status", "error"}, 1},
		{[]string{"--service", "Write", "--assoc", "3"}, 0},
	}
	for _, tc := range cases {
		args := append([]string{"transactions", "--format", "json", substation}, tc.args...)
		code, out, errs := cli(t, nil, args...)
		var doc document[transactionsJSON]
		if err := json.Unmarshal([]byte(out), &doc); code != exitOK || err != nil {
			t.Fatalf("%v: exit %d %v %s", tc.args, code, err, errs)
		}
		if n := len(doc.Files[0].Transactions); n != tc.rows {
			t.Errorf("%v: %d transactions, want %d", tc.args, n, tc.rows)
		}
	}
}

func TestEnvironment(t *testing.T) {
	t.Setenv("MMSTRACECTL_FORMAT", "json")
	code, out, _ := cli(t, nil, "goose", substation)
	if code != exitOK || !strings.HasPrefix(out, "{") {
		t.Errorf("MMSTRACECTL_FORMAT=json: exit %d %q", code, out)
	}
	code, out, _ = cli(t, nil, "goose", "--format", "text", substation)
	if code != exitOK || !strings.HasPrefix(out, "SRC") {
		t.Errorf("the flag wins: exit %d %q", code, out)
	}
	t.Setenv("MMSTRACECTL_FORMAT", "")
	t.Setenv("MMSTRACECTL_PORT", "x")
	if code, _, errs := cli(t, nil, "goose", substation); code != exitUsage || !strings.Contains(errs, "MMSTRACECTL_PORT") {
		t.Errorf("bad variable: exit %d %s", code, errs)
	}
}

func TestOtherPorts(t *testing.T) {
	code, out, _ := cli(t, nil, "info", "--format", "json", "--port", "502", substation)
	var doc document[infoJSON]
	if err := json.Unmarshal([]byte(out), &doc); code != exitOK || err != nil {
		t.Fatalf("exit %d %v", code, err)
	}
	if f := doc.Files[0]; f.Associations != 0 || f.Unsupported["other_tcp"] == 0 || f.GooseStreams != 1 {
		t.Errorf("port 502: %+v", f)
	}
}

type brokenPipe struct{ n int }

func (b *brokenPipe) Write(p []byte) (int, error) {
	if b.n <= 0 {
		return 0, os.ErrClosed
	}
	b.n--
	return len(p), nil
}

// TestWriteErrors: an output that goes away fails the command with 10.
func TestWriteErrors(t *testing.T) {
	for _, cmd := range []string{"info", "associations", "transactions", "reports", "goose", "sv", "version"} {
		for _, format := range []string{"text", "json", "csv"} {
			args := []string{cmd, "--format", format}
			if cmd != "version" {
				args = append(args, substation)
			}
			code, _, _ := cli(t, nil, args...)
			if code == exitUsage {
				continue // a format the command does not write
			}
			var errw bytes.Buffer
			if code := run(context.Background(), args, bytes.NewReader(nil), &brokenPipe{}, &errw); code != exitInternal {
				t.Errorf("%v: exit %d with a broken stdout", args, code)
			}
		}
	}
}

func TestInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errw bytes.Buffer
	if code := run(ctx, []string{"info", substation}, bytes.NewReader(nil), &out, &errw); code != exitInterrupted ||
		!strings.Contains(errw.String(), "interrupted") {
		t.Errorf("exit %d %q", code, errw.String())
	}
}

func TestExitCode(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		err  error
		code int
	}{
		{nil, exitOK},
		{errors.New("unknown command \"x\" for \"mmstracectl\""), exitUsage},
		{&outputError{os.ErrClosed}, exitInternal},
		{inputErr(os.ErrNotExist), exitInvalidInput},
		{trace.ErrCorrupt, exitInvalidInput},
		{context.Canceled, exitInterrupted},
		{errors.New("a bug"), exitInternal},
	}
	for _, tc := range cases {
		if got := exitCode(ctx, tc.err); got != tc.code {
			t.Errorf("%v: %d, want %d", tc.err, got, tc.code)
		}
	}
	if inputErr(nil) != nil {
		t.Error("inputErr(nil) is not nil")
	}
	if e := (&outputError{os.ErrClosed}); !errors.Is(e, os.ErrClosed) || e.Error() != os.ErrClosed.Error() {
		t.Error("outputError does not wrap")
	}
}

func TestHelpers(t *testing.T) {
	if objectName(mmsName(2, "", "x")) != "@/x" || objectName(mmsName(0, "", "y")) != "y" {
		t.Error("objectName")
	}
	if jsonTime(0) != "" || textTime(0) != "-" || csvTime(0) != "" || frame(0) != "" || vlan(5) != "5" || dash("a") != "a" {
		t.Error("formatting helpers")
	}
	if reportName(reportJSON{ListName: "LD0/ds"}) != "LD0/ds" || statusText(nil) != "-" {
		t.Error("report or status text")
	}
	if object(&trace.Transaction{}) != "" {
		t.Error("object of an empty transaction")
	}
}
