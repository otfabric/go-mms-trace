// SPDX-License-Identifier: MIT

package trace

import (
	"fmt"
	"math"
	"testing"
)

// TestGooseSequenceBoundaries: stNum and sqNum are compared at every edge
// of their 32 bits. Retransmissions of a state are no change whatever its
// number; the state after 4294967295 is 1 (nextStNum); everything else is
// reported as before.
func TestGooseSequenceBoundaries(t *testing.T) {
	const top = math.MaxUint32
	type msg [2]uint32 // stNum, sqNum
	cases := []struct {
		name    string
		msgs    []msg
		changes int
		issues  string // fmt of the Issues map
	}{
		{"retransmissions of state 0", []msg{{0, 1}, {0, 2}, {0, 3}}, 0, "map[]"},
		{"retransmissions of state 1", []msg{{1, 0}, {1, 1}, {1, 2}}, 0, "map[]"},
		{"retransmissions of state 2^32-2", []msg{{top - 1, 1}, {top - 1, 2}, {top - 1, 3}}, 0, "map[]"},
		{"retransmissions of state 2^32-1", []msg{{top, 1}, {top, 2}, {top, 3}}, 0, "map[]"},
		{"state 0 to 1", []msg{{0, 5}, {1, 0}}, 1, "map[]"},
		{"state 1 to 2", []msg{{1, 5}, {2, 0}}, 1, "map[]"},
		{"state 2^32-3 to 2^32-2 to 2^32-1", []msg{{top - 2, 1}, {top - 1, 0}, {top, 0}}, 2, "map[]"},
		{"state 2^32-1 to 1: the rollover", []msg{{top, 7}, {1, 0}, {1, 1}, {2, 0}}, 2, "map[]"},
		{"state 2^32-1 to 0", []msg{{top, 7}, {0, 0}}, 0, "map[stNum decreased:1]"},
		{"state 2^32-1 to 2", []msg{{top, 7}, {2, 0}}, 0, "map[stNum decreased:1]"},
		{"state 2^32-2 to 1", []msg{{top - 1, 7}, {1, 0}}, 0, "map[stNum decreased:1]"},
		{"state 0 to 2", []msg{{0, 1}, {2, 0}}, 1, "map[stNum jumped:1]"},
		{"state 1 to 3", []msg{{1, 1}, {3, 0}}, 1, "map[stNum jumped:1]"},
		{"state 0 to 2^32-1", []msg{{0, 1}, {top, 0}}, 1, "map[stNum jumped:1]"},
		{"state 2^32-3 to 2^32-1", []msg{{top - 2, 1}, {top, 0}}, 1, "map[stNum jumped:1]"},
		{"state 5 to 4", []msg{{5, 1}, {4, 0}}, 0, "map[stNum decreased:1]"},
		{"state 1 to 0", []msg{{1, 1}, {0, 0}}, 0, "map[stNum decreased:1]"},
		{"sqNum 0 to 1 to 2", []msg{{3, 0}, {3, 1}, {3, 2}}, 0, "map[]"},
		{"sqNum 0 to 2", []msg{{3, 0}, {3, 2}}, 0, "map[sqNum gap:1]"},
		{"sqNum 2^32-3 to 2^32-2 to 2^32-1", []msg{{3, top - 2}, {3, top - 1}, {3, top}}, 0, "map[]"},
		{"sqNum 2^32-3 to 2^32-1", []msg{{3, top - 2}, {3, top}}, 0, "map[sqNum gap:1]"},
		{"sqNum 0 to 2^32-1", []msg{{3, 0}, {3, top}}, 0, "map[sqNum gap:1]"},
		{"sqNum 2^32-1 to 1: its rollover", []msg{{3, top}, {3, 1}}, 0, "map[]"},
		{"sqNum 2^32-1 to 0", []msg{{3, top}, {3, 0}}, 0, "map[]"},
		{"sqNum falls", []msg{{3, 9}, {3, 4}}, 0, "map[]"},
		{"the same message twice", []msg{{3, 9}, {3, 9}}, 0, "map[repeated (stNum, sqNum):1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapture(t)
			for _, m := range tc.msgs {
				c.goose(t, m[0], m[1])
			}
			res := analyze(t, c.bytes(t))
			if len(res.GOOSE) != 1 {
				t.Fatalf("%d streams, GOOSE errors %d", len(res.GOOSE), res.Counters.GOOSEErrors)
			}
			g := res.GOOSE[0]
			if got := fmt.Sprint(g.Issues); g.Changes != tc.changes || got != tc.issues || g.Messages != len(tc.msgs) {
				t.Errorf("%d messages, %d changes, issues %s; want %d changes, %s", g.Messages, g.Changes, got, tc.changes, tc.issues)
			}
		})
	}
}
