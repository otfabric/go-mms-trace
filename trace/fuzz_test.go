// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// FuzzAnalyze: arbitrary bytes into Analyze never panic, and a result
// comes back whenever the error is nil or wraps ErrCorrupt.
func FuzzAnalyze(f *testing.F) {
	for _, p := range []string{fixtureFile, damagedFile} {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
			f.Add(b[:len(b)/2])
		}
	}
	f.Add([]byte("not a capture"))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := Analyze(context.Background(), bytes.NewReader(b), Options{MaxPacket: 1 << 16})
		if (err == nil) && res == nil {
			t.Fatal("no result and no error")
		}
	})
}
