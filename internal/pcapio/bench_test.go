// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

// benchPackets keeps the count of the last pass alive.
var benchPackets int

// BenchmarkReader measures reading every packet of a capture of 20,000
// packets of 200 bytes: pcap, pcapng, and pcap as gzip. The hash of the
// input is part of the read. The throughput is per byte of input.
func BenchmarkReader(b *testing.B) {
	packets := make([][]byte, 20_000)
	for i := range packets {
		packets[i] = bytes.Repeat([]byte{byte(i)}, 200)
	}
	files := captures(b, packets...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(files["pcap"])
	_ = zw.Close()
	for _, in := range []struct {
		name string
		file []byte
	}{{"pcap", files["pcap"]}, {"pcapng", files["pcapng"]}, {"pcap-gzip", gz.Bytes()}} {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.file)))
			b.ReportAllocs()
			for b.Loop() {
				rd, err := NewReader(bytes.NewReader(in.file), Options{})
				if err != nil {
					b.Fatal(err)
				}
				var p Packet
				n := 0
				for {
					if err := rd.Next(&p); err != nil {
						if err != io.EOF {
							b.Fatal(err)
						}
						break
					}
					n++
				}
				if n != len(packets) {
					b.Fatalf("%d packets", n)
				}
				benchPackets = n
			}
		})
	}
}
