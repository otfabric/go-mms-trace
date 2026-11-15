// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/otfabric/go-cotp"
	mms "github.com/otfabric/go-mms"
)

// exchange is one Read of a real association: the units that set the
// association up, and the Read's request and response. Variants of the
// two, told apart by content, make scripts in which every request has the
// same invoke ID.
type exchange struct {
	setup     []unit
	req, resp []byte
}

func readExchange(t testing.TB) exchange {
	t.Helper()
	units := recordAssociation(t, func(ctx context.Context, c *mms.Client) {
		if _, err := c.ReadObject(ctx, hz()); err != nil {
			t.Fatal(err)
		}
		_ = c.Abort(ctx)
	})
	var e exchange
	for i, u := range units {
		p, err := mms.DecodeTSDU(u.data)
		if err != nil || p.PDU == nil {
			continue
		}
		switch p.PDU.Kind {
		case "confirmed-request":
			e.setup, e.req = units[:i], u.data
		case "confirmed-response":
			e.resp = u.data
		}
	}
	if e.req == nil || e.resp == nil || len(e.setup) < 2 {
		t.Fatalf("no Read in the %d recorded units", len(units))
	}
	return e
}

// request returns the Read request for item i (0 to 9): the same PDU, the
// same invoke ID, another item name.
func (e exchange) request(t *testing.T, i int) []byte {
	t.Helper()
	b := bytes.Replace(e.req, []byte("MMXU1$MX$Hz"), []byte(fmt.Sprintf("MMXU1$MX$H%d", i)), 1)
	if p, err := mms.DecodeTSDU(b); err != nil || item(p.PDU) != i {
		t.Fatalf("request %d: %v", i, err)
	}
	return b
}

// response returns the Read response with value i.
func (e exchange) response(t *testing.T, i int) []byte {
	t.Helper()
	b := bytes.Replace(e.resp, []byte{0x85, 0x01, 50}, []byte{0x85, 0x01, byte(i)}, 1)
	if p, err := mms.DecodeTSDU(b); err != nil || value(p.PDU) != i {
		t.Fatalf("response %d: %v", i, err)
	}
	return b
}

// item is the number a request of the script reads, or -1.
func item(p *mms.CapturedPDU) int {
	if p == nil || len(p.Variables) != 1 {
		return -1
	}
	name := string(p.Variables[0].Name.ItemID)
	if !strings.HasPrefix(name, "MMXU1$MX$H") || len(name) != 11 {
		return -1
	}
	return int(name[10] - '0')
}

// value is the number a response of the script carries, or -1.
func value(p *mms.CapturedPDU) int {
	if p == nil || len(p.Values) != 1 {
		return -1
	}
	v, ok := p.Values[0].Int64()
	if !ok {
		return -1
	}
	return int(v)
}

// step is one unit of a script: who sends it (0 the client, 1 the
// server), and whether the capture holds it.
type step struct {
	from int
	tsdu []byte
	lost bool
}

// play writes the steps as COTP data on the capture's connection. A step
// the capture does not hold takes its sequence numbers all the same: a
// segment that was sent, received and acknowledged, and not captured.
func (c *capture) play(steps []step) {
	for _, s := range steps {
		b := tpkt(marshal(c.t, &cotp.DT{EOT: true, UserData: s.tsdu}))
		if s.lost {
			c.seq[s.from] += uint32(len(b))
			continue
		}
		c.tcp(s.from, 0x18, b)
	}
}

// outcome is a transaction of a script: the item its request reads and the
// value its response carries (-1 without one), and its status.
type outcome struct {
	item, value int
	status      string
}

func outcomes(res *Result) []outcome {
	var out []outcome
	for _, tr := range res.Transactions {
		out = append(out, outcome{item(tr.Request), value(tr.Response), tr.Status})
	}
	return out
}

// TestPairingAcrossLoss: a response is paired with the request that has
// its invoke ID as "ok" only when the capture holds everything the two
// sides sent in between. Every request of these scripts has the same invoke
// ID; request i reads item i and its answer carries value i.
func TestPairingAcrossLoss(t *testing.T) {
	e := readExchange(t)
	q := func(i int) step { return step{0, e.request(t, i), false} }
	a := func(i int) step { return step{1, e.response(t, i), false} }
	lost := func(s step) step { s.lost = true; return s }
	other := func(from int) step { return step{from, make([]byte, 40), true} } // bytes that were not captured
	cases := []struct {
		name  string
		steps []step
		want  []outcome
		gaps  int
	}{
		{"everything captured", []step{q(0), a(0), q(1), a(1)},
			[]outcome{{0, 0, StatusOK}, {1, 1, StatusOK}}, 0},
		{"an answer and the next request not captured", []step{q(0), lost(a(0)), lost(q(1)), a(1)},
			[]outcome{{0, 1, StatusUncertain}}, 2},
		{"an answer and the next request not captured, then a complete exchange", []step{q(0), lost(a(0)), lost(q(1)), a(1), q(2), a(2)},
			[]outcome{{0, 1, StatusUncertain}, {2, 2, StatusOK}}, 2},
		{"a request never answered, the next request not captured", []step{q(0), lost(q(1)), a(1)},
			[]outcome{{0, 1, StatusUncertain}}, 1},
		{"a request never answered, the next not captured, then a complete exchange", []step{q(0), lost(q(1)), a(1), q(2), a(2)},
			[]outcome{{0, 1, StatusUncertain}, {2, 2, StatusOK}}, 1},
		{"an answer not captured: the next exchange is whole", []step{q(0), lost(a(0)), q(1), a(1)},
			[]outcome{{0, -1, StatusUnanswered}, {1, 1, StatusOK}}, 1},
		{"a request not captured: its answer has no request", []step{q(0), a(0), lost(q(1)), a(1)},
			[]outcome{{0, 0, StatusOK}, {-1, 1, StatusOrphan}}, 1},
		{"two exchanges not captured in between", []step{q(0), lost(a(0)), lost(q(1)), lost(a(1)), lost(q(2)), a(2)},
			[]outcome{{0, 2, StatusUncertain}}, 2},
		{"bytes of the answering side lost while the request waits", []step{q(0), other(1), a(0)},
			[]outcome{{0, 0, StatusUncertain}}, 1},
		{"bytes of the answering side lost before the request was sent", []step{other(1), q(0), a(0)},
			[]outcome{{0, 0, StatusOK}}, 1},
		{"bytes of the requesting side lost while the request waits", []step{q(0), other(0), a(0)},
			[]outcome{{0, 0, StatusUncertain}}, 1},
		{"bytes of the requesting side lost before the request", []step{other(0), q(0), a(0)},
			[]outcome{{0, 0, StatusOK}}, 1},
	}
	for _, mirror := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name
			if mirror {
				name += ", requests of the server"
			}
			t.Run(name, func(t *testing.T) {
				c := newCapture(t)
				c.handshake()
				c.units(e.setup, false)
				script := make([]step, len(tc.steps))
				for i, s := range tc.steps {
					if mirror {
						s.from = 1 - s.from
					}
					script[i] = s
				}
				c.play(script)
				c.close()
				res := analyze(t, c.bytes(t))
				if got := fmt.Sprint(outcomes(res)); got != fmt.Sprint(tc.want) {
					t.Errorf("transactions (item, value, status): %s, want %v", got, tc.want)
				}
				if len(res.Associations) != 1 || res.Associations[0].Gaps != tc.gaps {
					t.Fatalf("%d associations, gaps %d, want %d", len(res.Associations), res.Associations[0].Gaps, tc.gaps)
				}
				for _, tr := range res.Transactions {
					if tr.ServerRequest != mirror {
						t.Errorf("a request of the server: %v, want %v", tr.ServerRequest, mirror)
					}
					if tr.Status == StatusUncertain && (tr.Request == nil || tr.Response == nil || tr.Response.Kind != "confirmed-response" || tr.LatencyNS() <= 0) {
						t.Errorf("an uncertain transaction without its PDUs or times: %+v", tr)
					}
				}
			})
		}
	}
}

// TestPairingNeverCrossesLoss: scripts of exchanges that all use one invoke
// ID, with units left out of the capture at random and some requests never
// answered. Whatever is lost, no transaction with a certain status pairs a
// request with the answer to another: in the whole script request i is
// answered by value i. A failure names the seed.
func TestPairingNeverCrossesLoss(t *testing.T) {
	e := readExchange(t)
	var reqs, resps [10][]byte
	for i := range reqs {
		reqs[i], resps[i] = e.request(t, i), e.response(t, i)
	}
	seeds := 400
	if testing.Short() {
		seeds = 100
	}
	certain, crossed := 0, 0
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(uint64(seed), 61850))
		var script []step
		var text []string
		for i := range 2 + rng.IntN(8) {
			req := step{0, reqs[i], rng.IntN(100) < 30}
			script = append(script, req)
			text = append(text, fmt.Sprintf("q%d lost=%v", i, req.lost))
			if rng.IntN(100) < 80 {
				resp := step{1, resps[i], rng.IntN(100) < 30}
				script = append(script, resp)
				text = append(text, fmt.Sprintf("a%d lost=%v", i, resp.lost))
			}
		}
		c := newCapture(t)
		c.handshake()
		c.units(e.setup, false)
		c.play(script)
		if rng.IntN(2) == 0 {
			c.close() // else the capture ends with the connection open
		}
		res := analyze(t, c.bytes(t))
		for _, o := range outcomes(res) {
			switch {
			case o.item < 0 || o.value < 0:
			case o.status == StatusUncertain:
				if o.item != o.value {
					crossed++
				}
			case o.item != o.value:
				t.Errorf("seed %d: request %d is paired with the answer to request %d as %q; script: %s", seed, o.item, o.value, o.status, strings.Join(text, ", "))
			default:
				certain++
			}
		}
	}
	if certain < seeds || crossed < seeds/20 {
		t.Errorf("%d certain pairs and %d pairs across a loss reported as uncertain in %d scripts: the scripts do not exercise the rule", certain, crossed, seeds)
	}
}
