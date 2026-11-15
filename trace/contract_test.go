// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-cotp"
	mms "github.com/otfabric/go-mms"

	"github.com/otfabric/go-mms-trace/internal/flow"
)

// failing is a reader that fails with err after n bytes of data.
type failing struct {
	data []byte
	n    int
	err  error
}

func (f *failing) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, f.err
	}
	n := copy(p, f.data[:min(f.n, len(f.data))])
	f.data, f.n = f.data[n:], f.n-n
	return n, nil
}

func fixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestErrorChain: what ended the read is in the error chain of Analyze, so
// that a caller tells a failed read of its own reader from a damaged file
// and from an input that is no capture.
func TestErrorChain(t *testing.T) {
	file := fixture(t)
	cause := errors.New("device gone")
	gz := gzipped(t, file)
	badCRC := bytes.Clone(gz)
	badCRC[len(badCRC)-8] ^= 0xff
	badSize := bytes.Clone(gz)
	badSize[len(badSize)-1] ^= 0xff
	cases := []struct {
		name    string
		r       io.Reader
		is, not []error
		result  bool
	}{
		{"a read error at the first byte", &failing{file, 0, cause}, []error{ErrFormat, cause}, []error{ErrCorrupt, ErrLimit}, false},
		{"a read error inside the file header", &failing{file, 10, cause}, []error{ErrFormat, cause}, []error{ErrCorrupt}, false},
		{"a read error inside the gzip stream, before the format is known", &failing{gz, 12, cause}, []error{ErrFormat, cause}, []error{ErrCorrupt}, false},
		{"a read error in the middle of the file", &failing{file, len(file) / 2, cause}, []error{ErrCorrupt, cause}, []error{ErrFormat, ErrLimit}, true},
		{"a read error in the middle of a gzip file", &failing{gz, len(gz) / 2, cause}, []error{ErrCorrupt, cause}, []error{ErrFormat}, true},
		{"a read error at the end of the file", &failing{file, len(file), cause}, []error{ErrCorrupt, cause}, []error{ErrFormat}, true},
		{"a deadline in the middle of the file", &failing{file, 3000, os.ErrDeadlineExceeded}, []error{ErrCorrupt, os.ErrDeadlineExceeded}, []error{ErrFormat}, true},
		{"a gzip checksum that does not match", bytes.NewReader(badCRC), []error{ErrCorrupt, gzip.ErrChecksum}, []error{ErrFormat, cause}, true},
		{"a gzip length that does not match", bytes.NewReader(badSize), []error{ErrCorrupt, gzip.ErrChecksum}, []error{ErrFormat}, true},
		{"a gzip header that is none", bytes.NewReader([]byte{0x1f, 0x8b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), []error{ErrFormat, gzip.ErrHeader}, []error{ErrCorrupt}, false},
		{"an empty input", bytes.NewReader(nil), []error{ErrFormat}, []error{ErrCorrupt, io.EOF, io.ErrUnexpectedEOF}, false},
		{"a file header cut short", bytes.NewReader(file[:10]), []error{ErrFormat}, []error{ErrCorrupt, io.EOF, io.ErrUnexpectedEOF}, false},
		{"an input past the limit", bytes.NewReader(file), []error{ErrLimit}, []error{ErrCorrupt, ErrFormat}, true},
	}
	for _, tc := range cases {
		o := Options{}
		if tc.name == "an input past the limit" {
			o.MaxBytes = int64(len(file) / 2)
		}
		res, err := Analyze(context.Background(), tc.r, o)
		for _, want := range tc.is {
			if !errors.Is(err, want) {
				t.Errorf("%s: the error %q does not wrap %q", tc.name, err, want)
			}
		}
		for _, not := range tc.not {
			if errors.Is(err, not) {
				t.Errorf("%s: the error %q wraps %q", tc.name, err, not)
			}
		}
		if (res != nil) != tc.result {
			t.Errorf("%s: result %v, want %v", tc.name, res != nil, tc.result)
		}
		// The result holds what was read before the error: every packet when
		// the error came after the last one (the checksum of a gzip stream
		// follows its data), some of them otherwise.
		whole := strings.HasPrefix(tc.name, "a gzip") || strings.HasSuffix(tc.name, "at the end of the file")
		if tc.result && (res.File.Packets == 0 || res.File.Packets > 61 || (res.File.Packets == 61) != whole) {
			t.Errorf("%s: %d packets in the result", tc.name, res.File.Packets)
		}
	}
}

// dump writes every value reachable from v, unexported fields included, in
// a form that two equal results share and that names no address.
func dump(w *strings.Builder, v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			w.WriteString("nil")
			return
		}
		w.WriteString("&")
		dump(w, v.Elem())
	case reflect.Struct:
		w.WriteString(v.Type().Name() + "{")
		for i := range v.NumField() {
			w.WriteString(v.Type().Field(i).Name + ":")
			dump(w, v.Field(i))
			w.WriteString(" ")
		}
		w.WriteString("}")
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			w.WriteString("nil")
			return
		}
		w.WriteString("[")
		for i := range v.Len() {
			dump(w, v.Index(i))
			w.WriteString(" ")
		}
		w.WriteString("]")
	case reflect.Map:
		var entries []string
		for it := v.MapRange(); it.Next(); {
			var e strings.Builder
			dump(&e, it.Key())
			e.WriteString("=")
			dump(&e, it.Value())
			entries = append(entries, e.String())
		}
		sort.Strings(entries)
		fmt.Fprintf(w, "map%v", entries)
	case reflect.String:
		fmt.Fprintf(w, "%q", v.String())
	case reflect.Bool:
		fmt.Fprint(w, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprint(w, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprint(w, v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprint(w, v.Float())
	default:
		fmt.Fprintf(w, "<%s>", v.Kind())
	}
}

func dumpResult(res *Result) string {
	var w strings.Builder
	dump(&w, reflect.ValueOf(res))
	return w.String()
}

// scribble overwrites everything a caller can reach from v through
// exported fields: the elements of slices, the entries of maps, the fields
// of structs behind pointers.
func scribble(v reflect.Value, seen map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		scribble(v.Elem(), seen)
	case reflect.Interface:
		if !v.IsNil() {
			scribble(v.Elem(), seen)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				scribble(v.Field(i), seen)
			}
		}
	case reflect.Slice:
		for i := range v.Len() {
			scribble(v.Index(i), seen)
		}
		if v.CanSet() && v.Len() > 0 {
			v.Set(v.Slice(0, v.Len()-1)) // and one element less
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			v.SetMapIndex(k, reflect.Value{})
		}
		if v.Type().Key().Kind() == reflect.String && v.Type().Elem().Kind() != reflect.Interface {
			v.SetMapIndex(reflect.ValueOf("scribbled").Convert(v.Type().Key()), reflect.Zero(v.Type().Elem()))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString("scribbled")
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(!v.Bool())
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() {
			v.SetInt(^v.Int() & 0x7f)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() {
			v.SetUint(^v.Uint() & 0x7f)
		}
	default: // arrays, floats, functions and channels: a Result has none a caller can reach
	}
}

// TestResultIsOwned: the caller owns the Result and everything reachable
// from it, and the library keeps no reference to it or to the input.
// Overwriting the input after the call changes nothing in the result;
// overwriting the result changes nothing in the next one.
func TestResultIsOwned(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("..", "testdata", "captures", "interop", "*ied-client*.pcap"))
	if err != nil || len(names) < 3 {
		t.Fatalf("interop captures: %v, %v", names, err)
	}
	files := map[string][]byte{fixtureFile: fixture(t)}
	ports := map[string][]uint16{fixtureFile: nil}
	for _, n := range names[:3] {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		files[n], ports[n] = b, []uint16{1102}
	}
	for name, file := range files {
		o := Options{Ports: ports[name]}
		first, err := Analyze(context.Background(), bytes.NewReader(bytes.Clone(file)), o)
		if err != nil {
			t.Fatal(err)
		}
		golden := dumpResult(first)

		// The input belongs to the caller again when Analyze returns.
		in := bytes.Clone(file)
		res, err := Analyze(context.Background(), bytes.NewReader(in), o)
		if err != nil {
			t.Fatal(err)
		}
		for i := range in {
			in[i] = 0xa5
		}
		if got := dumpResult(res); got != golden {
			t.Errorf("%s: the result changed when the input was overwritten after the call", name)
		}
		tsaps := 0
		for _, as := range res.Associations {
			if as.CallingTSAP != nil {
				tsaps++
				// The fixture's connection requests all carry the same
				// selectors, and bytes of many packets follow them.
				if name == fixtureFile && (string(as.CallingTSAP) != "\x00\x01" || string(as.CalledTSAP) != "\x00\x01") {
					t.Errorf("association %d: TSAPs %x and %x", as.ID, as.CallingTSAP, as.CalledTSAP)
				}
			}
		}
		if tsaps == 0 {
			t.Errorf("%s: no association with TSAPs", name)
		}

		// The result belongs to the caller: writing to it reaches nothing
		// the library uses for the next analysis.
		scribble(reflect.ValueOf(res), map[uintptr]bool{})
		if got := dumpResult(res); got == golden {
			t.Fatalf("%s: the result was not overwritten", name)
		}
		again, err := Analyze(context.Background(), bytes.NewReader(file), o)
		if err != nil {
			t.Fatal(err)
		}
		if got := dumpResult(again); got != golden {
			t.Errorf("%s: the next result differs after the previous one was overwritten", name)
		}
	}
}

// TestDataIsNotKept: the bytes the TCP stage delivers are valid during the
// call only. What the analysis keeps of them (the TSAPs of a connection
// request, the start of a frame or of a TSDU that is not complete) is a
// copy: overwriting the delivered bytes after every call changes nothing.
func TestDataIsNotKept(t *testing.T) {
	report := informationReport(t)
	want, err := mms.DecodeTSDU(report)
	if err != nil {
		t.Fatal(err)
	}
	cr := tpkt(marshal(t, &cotp.CR{SourceRef: 1, CallingSelector: []byte{0xca, 0x11}, CalledSelector: []byte{0xca, 0x22}}))
	whole := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: report}))
	first, last := twoParts(t, report)
	a := newAnalyzer(Options{Ports: DefaultPorts, MaxAssembly: DefaultMaxAssembly})
	c := &flow.Conn{SYNFrom: 0, SYNACKFrom: 1, Endpoints: [2]netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.0.2:102")}}
	a.Open(c)
	pos := uint64(0)
	feed := func(b []byte) {
		buf := bytes.Clone(b)
		a.Data(c, 0, pos, buf, flow.Chunk{Frame: 1, TimeNS: 1})
		pos += uint64(len(buf))
		for i := range buf {
			buf[i] = 0xa5
		}
	}
	feed(cr)
	feed(whole[:30]) // a frame in two deliveries
	feed(whole[30:])
	feed(first) // a TSDU in two frames
	feed(last)
	feed(first[:10]) // and each of those in two deliveries
	feed(first[10:])
	feed(last[:5])
	feed(last[5:])
	feed(append(bytes.Clone(whole), whole[:20]...)) // a frame and the start of the next
	feed(whole[20:])
	if len(a.res.Associations) != 1 || string(a.res.Associations[0].CallingTSAP) != "\xca\x11" || string(a.res.Associations[0].CalledTSAP) != "\xca\x22" {
		t.Fatalf("associations %+v", a.res.Associations)
	}
	if n := len(a.res.Reports); n != 5 || a.res.Counters.TSDUErrors+a.res.Counters.COTPErrors+a.res.Counters.TPKTResync != 0 {
		t.Fatalf("%d reports, counters %+v", n, a.res.Counters)
	}
	var w strings.Builder
	dump(&w, reflect.ValueOf(want.PDU))
	for i, r := range a.res.Reports {
		var g strings.Builder
		dump(&g, reflect.ValueOf(r.PDU))
		if g.String() != w.String() {
			t.Errorf("report %d is not the report that was sent", i)
		}
	}
}

// cancelling is a reader that cancels a context once n bytes were read,
// and counts the bytes read.
type cancelling struct {
	r      io.Reader
	n      int
	read   int
	cancel context.CancelFunc
}

func (c *cancelling) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	if c.read >= c.n {
		c.cancel()
	}
	return n, err
}

// TestCancel: Analyze returns the context's error and no result when the
// context is done, before the first packet and in the middle of the pass,
// and it stops reading there.
func TestCancel(t *testing.T) {
	file := requests(t, readExchange(t), 48_000) // about 3 MB
	for name, when := range map[string]int{"before the first read": 0, "at the first read": 1, "in the middle of the pass": len(file) / 3} {
		ctx, cancel := context.WithCancel(context.Background())
		if when == 0 {
			cancel()
		}
		r := &cancelling{r: bytes.NewReader(file), n: when, cancel: cancel}
		res, err := Analyze(ctx, r, Options{})
		cancel()
		if !errors.Is(err, context.Canceled) || res != nil {
			t.Errorf("cancelled %s: err %v, result %v; want context.Canceled and no result", name, err, res != nil)
		}
		// The input is read in pieces of 256 KiB, and the pass stops at the
		// first packet after the cancellation.
		if limit := when + 2*256<<10; r.read > limit || (when == 0 && r.read > 256<<10) {
			t.Errorf("cancelled %s: %d of %d bytes were read", name, r.read, len(file))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if res, err := Analyze(ctx, bytes.NewReader(file), Options{}); !errors.Is(err, context.DeadlineExceeded) || res != nil {
		t.Errorf("a deadline that has passed: err %v, result %v", err, res != nil)
	}
}

// TestConcurrentAnalyze: calls on different readers run at the same time
// and share nothing: each returns what a call by itself returns.
func TestConcurrentAnalyze(t *testing.T) {
	file := fixture(t)
	damaged, err := os.ReadFile(damagedFile)
	if err != nil {
		t.Fatal(err)
	}
	alone, err := Analyze(context.Background(), bytes.NewReader(file), Options{})
	if err != nil {
		t.Fatal(err)
	}
	golden := dumpResult(alone)
	const workers, rounds = 16, 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				switch (w + r) % 4 {
				case 0: // a damaged capture next to the others
					if res, err := Analyze(context.Background(), bytes.NewReader(damaged), Options{}); !errors.Is(err, ErrCorrupt) || res == nil {
						errs <- fmt.Errorf("worker %d round %d: damaged capture: %v", w, r, err)
					}
				case 1: // other ports
					if res, err := Analyze(context.Background(), bytes.NewReader(file), Options{Ports: []uint16{1102}}); err != nil || len(res.Associations) != 0 {
						errs <- fmt.Errorf("worker %d round %d: other ports: %v", w, r, err)
					}
				default:
					res, err := Analyze(context.Background(), bytes.NewReader(file), Options{})
					if err != nil || dumpResult(res) != golden {
						errs <- fmt.Errorf("worker %d round %d: the result differs from a call by itself (%v)", w, r, err)
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
