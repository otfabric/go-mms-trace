// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"testing"

	"github.com/otfabric/go-cotp"
)

// benchResult keeps the last result alive.
var benchResult *Result

// exchanges builds a capture of one association with n Read requests and
// their responses, one TCP segment each.
func exchanges(t testing.TB, e exchange, n int) []byte {
	t.Helper()
	c := newCapture(t)
	c.handshake()
	c.units(e.setup, false)
	req := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: e.req}))
	resp := tpkt(marshal(t, &cotp.DT{EOT: true, UserData: e.resp}))
	for range n {
		c.tcp(0, 0x18, req)
		c.tcp(1, 0x18, resp)
	}
	c.close()
	return c.bytes(t)
}

// BenchmarkAnalyze measures a whole pass of Analyze, from the bytes of a
// capture to its Result, reader, TCP reassembly, ISO stack and MMS decoding
// included: the committed fixture (61 packets), a generated association of
// 20,000 Read exchanges, the same capture as gzip, 96,000 requests packed
// 24 to a segment (the most transactions per byte), and 20,000 GOOSE
// messages of one stream. The throughput is per byte of input.
func BenchmarkAnalyze(b *testing.B) {
	e := readExchange(b)
	polls := exchanges(b, e, 20_000)
	goose := newCapture(b)
	for i := range 20_000 {
		goose.goose(b, uint32(1+i/4), uint32(i%4))
	}
	inputs := []struct {
		name string
		file []byte
		tx   int
	}{
		{"fixture", fixture(b), 9},
		{"exchanges", polls, 20_000},
		{"exchanges-gzip", gzipped(b, polls), 20_000},
		{"requests", requests(b, e, 96_000), 96_000},
		{"goose", goose.bytes(b), 0},
	}
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.file)))
			b.ReportAllocs()
			for b.Loop() {
				res, err := Analyze(context.Background(), bytes.NewReader(in.file), Options{})
				if err != nil || len(res.Transactions) != in.tx {
					b.Fatalf("err %v, %d transactions, want %d", err, len(res.Transactions), in.tx)
				}
				benchResult = res
			}
		})
	}
}
