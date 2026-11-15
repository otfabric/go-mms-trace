// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	mms "github.com/otfabric/go-mms"

	"github.com/otfabric/go-mms-trace/trace"
)

func TestPrintable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"LD0/MMXU1$MX$Hz", "LD0/MMXU1$MX$Hz"},
		{" ~", " ~"},     // the first and the last printable ASCII character
		{"\x00", `\x00`}, // the C0 set, from its first
		{"\x1f", `\x1f`}, // to its last
		{"a\x07b\x09c\x0ad\x0de\x1bf", `a\x07b\x09c\x0ad\x0de\x1bf`},
		{"\x7f", `\x7f`},                       // DEL
		{"\u0080", `\x80`},                     // the C1 set, from its first
		{"\u009b", `\x9b`},                     // (the control sequence introducer)
		{"\u009f", `\x9f`},                     // to its last
		{"\u00a0é€", "\u00a0é€"},               // the characters after it stay
		{"\x80", `\x80`},                       // bytes that are not UTF-8
		{"\xff\xfe", `\xff\xfe`},               //
		{"\xc3", `\xc3`},                       // a sequence cut short
		{"é\x1bé", `é\x1bé`},                   // between characters of several bytes
		{`back\slash \x1b`, `back\slash \x1b`}, // a backslash stays as it is
		{"=1+1", "=1+1"},                       // and so does the start of a cell
		{"-x", "-x"},                           //
		{"@x", "@x"},                           //
		{"+x\x1b", `+x\x1b`},                   //
	}
	for _, tc := range cases {
		if got := printable(tc.in); got != tc.want {
			t.Errorf("printable(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// controls is what a name of a capture can hold besides printable text:
// an escape sequence, a bell, a line end of both kinds, a tab, DEL, a C1
// control and a byte that is not UTF-8.
const (
	controls        = "\x1b[0m\a\r\n\tX\x7f\u009b\xff"
	controlsPrinted = `\x1b[0m\x07\x0d\x0a\x09X\x7f\x9b\xff`
)

// namedResult is a result in which every string that comes from a capture
// holds the controls.
func namedResult() *trace.Result {
	name := func(item string) mms.ObjectName {
		return mms.ObjectName{Scope: mms.ObjectScopeDomain, Domain: mms.DomainID("LD" + controls), ItemID: mms.ItemID(item + controls)}
	}
	list := name("list")
	variable := name("var")
	ok := true
	return &trace.Result{
		File: trace.File{Format: "pcap", Packets: 6, Interfaces: 1, Links: []string{"ethernet"}},
		Associations: []*trace.Association{{ID: 1, Client: netip.MustParseAddrPort("10.0.0.1:40000"), Server: netip.MustParseAddrPort("10.0.0.2:102"),
			Open: "associate" + controls, Close: "abort" + controls, Accepted: &ok, Authentication: "other" + controls, Transactions: 6, Reports: 2}},
		Transactions: []*trace.Transaction{
			{Association: 1, InvokeID: 1, Service: "Read" + controls, Status: trace.StatusOK, RequestNS: 1e9, ResponseNS: 2e9,
				Request: &mms.CapturedPDU{Variables: []mms.CapturedVariable{{Name: name("a")}, {Name: name("b")}}}},
			{Association: 1, InvokeID: 2, Service: "Read", Status: trace.StatusUncertain, RequestNS: 3e9,
				Request: &mms.CapturedPDU{ListName: &list}},
			{Association: 1, InvokeID: 3, Service: "GetVariableAccessAttributes", Status: trace.StatusPending, RequestNS: 4e9,
				Request: &mms.CapturedPDU{VariableName: &variable}},
			{Association: 1, InvokeID: 4, Service: "GetNameList", Status: trace.StatusUnanswered, RequestNS: 5e9,
				Request: &mms.CapturedPDU{NameListRequest: &mms.CapturedNameListRequest{ObjectClass: 9, Scope: mms.ObjectScopeDomain, Domain: "LD" + controls}}},
			{Association: 1, InvokeID: 5, Service: "Identify", Status: trace.StatusOK, RequestNS: 6e9, ResponseNS: 7e9,
				Request:  &mms.CapturedPDU{},
				Response: &mms.CapturedPDU{Identify: &mms.CapturedIdentify{Vendor: "v" + controls, Model: "m" + controls, Revision: "r" + controls}}},
			{Association: 1, InvokeID: 6, Service: controls, Status: trace.StatusOrphan, ResponseNS: 8e9,
				Response: &mms.CapturedPDU{Variables: []mms.CapturedVariable{{Name: mms.ObjectName{Scope: mms.ObjectScopeVMD, ItemID: mms.ItemID(controls)}}}}},
		},
		Reports: []*trace.Report{
			{Association: 1, TimeNS: 9e9, Frame: 5, PDU: &mms.CapturedPDU{ListName: &list}},
			{Association: 1, TimeNS: 9e9, Frame: 6, PDU: &mms.CapturedPDU{Variables: []mms.CapturedVariable{{Name: name("a")}, {Name: name("b")}}}},
		},
		GOOSE: []*trace.GooseStream{{Src: "02:00:00:00:00:01", Dst: "01:0c:cd:01:00:01", GocbRef: "gcb" + controls, DatSet: "ds" + controls,
			GoID: "id" + controls, Messages: 3, Issues: map[string]int{"sqNum gap": 1}}},
		SV:       []*trace.SVStream{{Src: "02:00:00:00:00:02", Dst: "01:0c:cd:04:00:01", SvID: "sv" + controls, DatSet: "ds" + controls, ASDUs: 4, Lost: 1}},
		Counters: trace.Counters{Unsupported: map[string]uint64{"other_tcp": 1}},
	}
}

// checkPrintable fails when text or CSV output holds a control character
// other than the line ends of its rows, or bytes that are not UTF-8.
func checkPrintable(t *testing.T, what, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("%s: the output is not UTF-8", what)
	}
	for i, r := range out {
		if r != '\n' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			t.Errorf("%s: control character %#x at byte %d of the output", what, r, i)
			return
		}
	}
}

// TestTextAndCSVArePrintable: every string of a capture is written to text
// and CSV output as printable text. A name with control characters stays
// one cell of one row: the tables have a row for every item, the CSV
// records the fields of their header, and the controls show as \xNN.
func TestTextAndCSVArePrintable(t *testing.T) {
	as := []analysis{{name: "capture.pcap", res: namedResult()}}
	all := &transactionFilter{}
	outputs := []struct {
		name  string
		write func(w io.Writer, format string) error
		rows  int  // rows after the header
		named bool // the output holds names of the capture
	}{
		{"info", func(w io.Writer, f string) error { return writeInfo(w, as, f) }, -1, true},
		{"associations", func(w io.Writer, f string) error { return writeAssociations(w, as, f) }, 1, true},
		{"transactions", func(w io.Writer, f string) error { return writeTransactions(w, as, f, all) }, 6, true},
		{"reports", func(w io.Writer, f string) error { return writeReports(w, as, f) }, 2, true},
		{"goose", func(w io.Writer, f string) error { return writeGoose(w, as, f) }, 1, true},
		{"sv", func(w io.Writer, f string) error { return writeSV(w, as, f) }, 1, true},
	}
	for _, o := range outputs {
		var text bytes.Buffer
		if err := o.write(&text, formatText); err != nil {
			t.Fatal(err)
		}
		checkPrintable(t, o.name+" text", text.String())
		if lines := strings.Count(text.String(), "\n"); o.rows >= 0 && lines != o.rows+1 {
			t.Errorf("%s text: %d lines for %d rows and a header:\n%s", o.name, lines, o.rows, text.String())
		}
		if o.named && !strings.Contains(text.String(), controlsPrinted) {
			t.Errorf("%s text: the controls are not written as %s:\n%s", o.name, controlsPrinted, text.String())
		}
		// JSON has its own escaping: the document is valid and holds no raw control either.
		var j bytes.Buffer
		if err := o.write(&j, formatJSON); err != nil || !json.Valid(j.Bytes()) {
			t.Errorf("%s JSON: %v", o.name, err)
		}
		checkPrintable(t, o.name+" JSON", j.String())
		if o.name == "info" || o.name == "associations" {
			continue // no CSV
		}
		var c bytes.Buffer
		if err := o.write(&c, formatCSV); err != nil {
			t.Fatal(err)
		}
		checkPrintable(t, o.name+" CSV", c.String())
		records, err := csv.NewReader(&c).ReadAll() // it fails on a record with another number of fields
		if err != nil || len(records) != o.rows+1 {
			t.Errorf("%s CSV: %d records for %d rows and a header, %v", o.name, len(records), o.rows, err)
		}
		found := false
		for _, r := range records {
			for _, cell := range r {
				found = found || strings.Contains(cell, controlsPrinted)
			}
		}
		if !found {
			t.Errorf("%s CSV: the controls are not written as %s", o.name, controlsPrinted)
		}
	}
}

// TestControlCharactersOfACapture: the same from a capture to the output of
// the commands. The fixture's item name is overwritten, in the capture's
// bytes, by a name of the same length with an escape sequence, a bell, a
// line end and a tab.
func TestControlCharactersOfACapture(t *testing.T) {
	const name, with = "MMXU1$MX$Hz", "M\x1b[0m\a\r\n\tHz"
	file := readFixture(t)
	if len(name) != len(with) || bytes.Count(file, []byte(name)) < 5 {
		t.Fatalf("the fixture names %q %d times", name, bytes.Count(file, []byte(name)))
	}
	path := filepath.Join(t.TempDir(), "names.pcap")
	if err := os.WriteFile(path, bytes.ReplaceAll(file, []byte(name), []byte(with)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := cli(t, nil, "transactions", "--format", "json", path)
	var doc document[transactionsJSON]
	if err := json.Unmarshal([]byte(out), &doc); code != exitOK || err != nil {
		t.Fatalf("exit %d %v %s", code, err, errs)
	}
	rows, named := len(doc.Files[0].Transactions), 0
	for _, x := range doc.Files[0].Transactions {
		if strings.Contains(x.Object, with) {
			named++
		}
	}
	if rows != 9 {
		t.Fatalf("%d transactions", rows)
	}
	for _, cmd := range []string{"transactions", "reports", "associations", "info", "goose", "sv"} {
		code, text, errs := cli(t, nil, cmd, path)
		if code != exitOK {
			t.Fatalf("%s: exit %d %s", cmd, code, errs)
		}
		checkPrintable(t, cmd+" text", text)
		if cmd != "transactions" {
			continue
		}
		if lines := strings.Count(text, "\n"); lines != rows+1 {
			t.Errorf("transactions text: %d lines for %d transactions and a header", lines, rows)
		}
		code, c, _ := cli(t, nil, cmd, "--format", "csv", path)
		checkPrintable(t, "transactions CSV", c)
		records, err := csv.NewReader(strings.NewReader(c)).ReadAll()
		if code != exitOK || err != nil || len(records) != rows+1 {
			t.Errorf("transactions CSV: exit %d, %d records for %d transactions and a header, %v", code, len(records), rows, err)
		}
		// The name as the library decoded it is in the JSON document; text
		// and CSV write the same name in printable form.
		if printed := `LD0/M\x1b[0m\x07\x0d\x0a\x09Hz`; named > 0 && (strings.Count(text, printed) != named || strings.Count(c, printed) != named) {
			t.Errorf("%d transactions name the item; text writes it %d times as %s, CSV %d times", named, strings.Count(text, printed), printed, strings.Count(c, printed))
		}
	}
	if named == 0 {
		t.Log("the library did not decode a name with control characters: the printable form of a decoded name is covered by TestTextAndCSVArePrintable")
	}
}

// TestMaxBytesFlag: --max-bytes bounds what is read of a capture. A capture
// that goes on past it is reported like a damaged one: what was read is
// printed, then the error, exit 3.
func TestMaxBytesFlag(t *testing.T) {
	file := readFixture(t)
	size := int64(len(file))
	for _, tc := range []struct {
		max      int64
		lo, hi   uint64 // packets read
		complete bool
	}{
		{0, 61, 61, true}, {size, 61, 61, true}, {size + 1, 61, 61, true}, {1 << 62, 61, 61, true},
		{size - 1, 60, 60, false}, {3000, 1, 59, false}, {24, 0, 0, false}, {1, 0, 0, false},
	} {
		code, out, errs := cli(t, nil, "info", "--format", "json", "--max-bytes", strconv.FormatInt(tc.max, 10), substation)
		var doc document[infoJSON]
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("--max-bytes %d: exit %d, %v %s", tc.max, code, err, errs)
		}
		f := doc.Files[0]
		wantCode, wantRead := exitOK, size
		if !tc.complete {
			wantCode, wantRead = exitInvalidInput, max(tc.max, 24) // the file header is read whatever the limit
		}
		if code != wantCode || f.Packets < tc.lo || f.Packets > tc.hi || f.UncompressedBytes != wantRead || (f.Error == "") != tc.complete ||
			strings.Contains(errs, "limit") == tc.complete {
			t.Errorf("--max-bytes %d: exit %d, %d packets, %d bytes read of %d, error %q, stderr %q", tc.max, code, f.Packets, f.UncompressedBytes, size, f.Error, errs)
		}
	}
	for _, v := range []string{"-1", "x", "9223372036854775808"} {
		if code, out, errs := cli(t, nil, "info", "--max-bytes", v, substation); code != exitUsage || out != "" {
			t.Errorf("--max-bytes %s: exit %d, stdout %q, stderr %q", v, code, out, errs)
		}
	}
	// The limit is on the capture, not on the file: a gzip capture is
	// bounded by what it unpacks to.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(file)
	_ = zw.Close()
	path := filepath.Join(t.TempDir(), "fixture.pcap.gz")
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := cli(t, nil, "info", "--max-bytes", "3000", path)
	if code != exitInvalidInput || !strings.Contains(out, "gzip, ") || !strings.Contains(out, "(3000 uncompressed)") {
		t.Errorf("gzip: exit %d, stdout:\n%s", code, out)
	}
	if code, out, _ := cli(t, nil, "transactions", "--status", "uncertain", substation); code != exitOK || strings.Count(out, "\n") != 1 {
		t.Errorf("--status uncertain: exit %d, stdout %q", code, out)
	}
	t.Setenv("MMSTRACECTL_MAX_BYTES", "3000")
	if code, out, _ := cli(t, nil, "transactions", substation); code != exitInvalidInput || !strings.HasPrefix(out, "TIME") {
		t.Errorf("MMSTRACECTL_MAX_BYTES=3000: exit %d, stdout %q", code, out)
	}
}
