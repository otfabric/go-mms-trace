// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	mms "github.com/otfabric/go-mms"

	"github.com/otfabric/go-mms-trace/trace"
)

// The JSON documents (docs/json-output.md). They are defined here, not
// marshalled from the library's types, so that the output contract does not
// follow the library's Go API.

// schemaVersion is the version of every document but version's.
const schemaVersion = 1

// document is what every command but version writes with --format json.
type document[T any] struct {
	SchemaVersion int `json:"schema_version"`
	Files         []T `json:"files"`
}

// fileHeader starts the per-capture object of every document.
type fileHeader struct {
	File string `json:"file"`
	// Error is the damage that ended reading early.
	Error string `json:"error,omitempty"`
}

func header(a analysis) fileHeader {
	h := fileHeader{File: a.name}
	if a.err != nil {
		h.Error = a.err.Error()
	}
	return h
}

// infoJSON is one capture in the info document.
type infoJSON struct {
	fileHeader
	Format        string            `json:"format"`
	Gzip          bool              `json:"gzip"`
	SHA256        string            `json:"sha256"`
	InputBytes    int64             `json:"input_bytes"`
	Packets       uint64            `json:"packets"`
	Interfaces    int               `json:"interfaces"`
	Links         []string          `json:"links"`
	First         string            `json:"first,omitempty"`
	Last          string            `json:"last,omitempty"`
	TruncatedTail bool              `json:"truncated_tail"`
	SkippedBlocks uint64            `json:"skipped_blocks"`
	Associations  int               `json:"associations"`
	Transactions  int               `json:"transactions"`
	Statuses      map[string]int    `json:"statuses"`
	Reports       int               `json:"reports"`
	GooseStreams  int               `json:"goose_streams"`
	SVStreams     int               `json:"sv_streams"`
	Counters      countersJSON      `json:"counters"`
	Services      map[string]int    `json:"services"`
	Unsupported   map[string]uint64 `json:"unsupported"`
}

type countersJSON struct {
	TPKTResync  uint64 `json:"tpkt_resync"`
	COTPErrors  uint64 `json:"cotp_errors"`
	TSDUErrors  uint64 `json:"tsdu_errors"`
	BareMMS     uint64 `json:"bare_mms"`
	TSOSegments uint64 `json:"tso_segments"`
	GOOSEErrors uint64 `json:"goose_errors"`
	SVErrors    uint64 `json:"sv_errors"`
}

func toInfo(a analysis) infoJSON {
	r := a.res
	f := r.File
	out := infoJSON{fileHeader: header(a), Format: f.Format, Gzip: f.Gzip, SHA256: f.SHA256, InputBytes: f.InputBytes,
		Packets: f.Packets, Interfaces: f.Interfaces, Links: f.Links, First: jsonTime(f.FirstNS), Last: jsonTime(f.LastNS),
		TruncatedTail: f.TruncatedTail, SkippedBlocks: f.SkippedBlocks,
		Associations: len(r.Associations), Transactions: len(r.Transactions), Statuses: map[string]int{},
		Reports: len(r.Reports), GooseStreams: len(r.GOOSE), SVStreams: len(r.SV), Services: map[string]int{},
		Counters: countersJSON{TPKTResync: r.Counters.TPKTResync, COTPErrors: r.Counters.COTPErrors, TSDUErrors: r.Counters.TSDUErrors,
			BareMMS: r.Counters.BareMMS, TSOSegments: r.Counters.TSOSegments, GOOSEErrors: r.Counters.GOOSEErrors, SVErrors: r.Counters.SVErrors},
		Unsupported: maps.Clone(r.Counters.Unsupported)}
	if out.Links == nil {
		out.Links = []string{}
	}
	if out.Unsupported == nil {
		out.Unsupported = map[string]uint64{}
	}
	for _, t := range r.Transactions {
		out.Statuses[t.Status]++
		out.Services[t.Service]++
	}
	return out
}

// associationJSON is one association.
type associationJSON struct {
	ID             int    `json:"id"`
	Client         string `json:"client"`
	Server         string `json:"server"`
	Open           string `json:"open"`
	Close          string `json:"close"`
	Accepted       *bool  `json:"accepted"`
	Authentication string `json:"authentication"`
	CallingTSAP    string `json:"calling_tsap"`
	CalledTSAP     string `json:"called_tsap"`
	Transactions   int    `json:"transactions"`
	Reports        int    `json:"reports"`
	Unanswered     int    `json:"unanswered"`
	Gaps           int    `json:"gaps"`
	First          string `json:"first,omitempty"`
	Last           string `json:"last,omitempty"`
}

type associationsJSON struct {
	fileHeader
	Associations []associationJSON `json:"associations"`
}

func toAssociation(as *trace.Association) associationJSON {
	return associationJSON{ID: as.ID, Client: as.Client.String(), Server: as.Server.String(), Open: as.Open, Close: as.Close,
		Accepted: as.Accepted, Authentication: as.Authentication,
		CallingTSAP: hex.EncodeToString(as.CallingTSAP), CalledTSAP: hex.EncodeToString(as.CalledTSAP),
		Transactions: as.Transactions, Reports: as.Reports, Unanswered: as.Unanswered, Gaps: as.Gaps,
		First: jsonTime(as.FirstNS), Last: jsonTime(as.LastNS)}
}

// transactionJSON is one confirmed service.
type transactionJSON struct {
	Time          string        `json:"time,omitempty"`
	Association   int           `json:"association"`
	InvokeID      uint32        `json:"invoke_id"`
	Service       string        `json:"service"`
	Status        string        `json:"status"`
	LatencyMS     *float64      `json:"latency_ms"`
	Object        string        `json:"object"`
	RequestFrame  uint64        `json:"request_frame,omitempty"`
	ResponseFrame uint64        `json:"response_frame,omitempty"`
	Error         *serviceError `json:"error,omitempty"`
	Reject        *rejectJSON   `json:"reject,omitempty"`
}

// serviceError is the class and code of a confirmed error (ISO 9506-2).
type serviceError struct {
	Class int `json:"class"`
	Code  int `json:"code"`
}

// rejectJSON is the rejected PDU type and the reason of a reject PDU.
type rejectJSON struct {
	Type   int `json:"type"`
	Reason int `json:"reason"`
}

type transactionsJSON struct {
	fileHeader
	Transactions []transactionJSON `json:"transactions"`
}

// transactionTime is when a transaction was first seen: its request, or
// its response when the request was not captured.
func transactionTime(t *trace.Transaction) int64 {
	if t.RequestNS != 0 {
		return t.RequestNS
	}
	return t.ResponseNS
}

func toTransaction(t *trace.Transaction) transactionJSON {
	out := transactionJSON{Time: jsonTime(transactionTime(t)), Association: t.Association, InvokeID: t.InvokeID,
		Service: t.Service, Status: t.Status, Object: object(t), RequestFrame: t.RequestFrame, ResponseFrame: t.ResponseFrame}
	if l := t.LatencyNS(); l >= 0 {
		ms := float64(l) / 1e6
		out.LatencyMS = &ms
	}
	if p := t.Response; p != nil {
		if p.Error != nil {
			out.Error = &serviceError{Class: p.Error.Class, Code: p.Error.Code}
		}
		if p.Reject != nil {
			out.Reject = &rejectJSON{Type: p.Reject.Type, Reason: p.Reject.Reason}
		}
	}
	return out
}

// sortedTransactions returns the transactions in time order (stable, so
// equal times keep capture order).
func sortedTransactions(ts []*trace.Transaction) []*trace.Transaction {
	out := slices.Clone(ts)
	sort.SliceStable(out, func(i, j int) bool { return transactionTime(out[i]) < transactionTime(out[j]) })
	return out
}

// reportJSON is one InformationReport.
type reportJSON struct {
	Time        string   `json:"time,omitempty"`
	Association int      `json:"association"`
	Frame       uint64   `json:"frame"`
	ListName    string   `json:"list_name,omitempty"`
	Variables   []string `json:"variables"`
	Values      int      `json:"values"`
}

type reportsJSON struct {
	fileHeader
	Reports []reportJSON `json:"reports"`
}

func toReport(r *trace.Report) reportJSON {
	out := reportJSON{Time: jsonTime(r.TimeNS), Association: r.Association, Frame: r.Frame, Variables: []string{}}
	if p := r.PDU; p != nil {
		if p.ListName != nil {
			out.ListName = objectName(*p.ListName)
		}
		for _, v := range p.Variables {
			out.Variables = append(out.Variables, objectName(v.Name))
		}
		out.Values = len(p.Values)
	}
	return out
}

// reportName is the list name of a report, or its variables.
func reportName(r reportJSON) string {
	if r.ListName != "" {
		return r.ListName
	}
	return strings.Join(r.Variables, " ")
}

// gooseJSON is one GOOSE stream.
type gooseJSON struct {
	Src          string         `json:"src"`
	Dst          string         `json:"dst"`
	AppID        uint16         `json:"app_id"`
	VLAN         int            `json:"vlan"`
	GocbRef      string         `json:"gocb_ref"`
	DatSet       string         `json:"dat_set"`
	GoID         string         `json:"go_id"`
	ConfRev      uint32         `json:"conf_rev"`
	Messages     int            `json:"messages"`
	Changes      int            `json:"changes"`
	Simulation   int            `json:"simulation"`
	NdsCom       int            `json:"nds_com"`
	MaxPerSecond int            `json:"max_per_second"`
	First        string         `json:"first,omitempty"`
	Last         string         `json:"last,omitempty"`
	Issues       map[string]int `json:"issues"`
}

type gooseStreamsJSON struct {
	fileHeader
	Streams []gooseJSON `json:"streams"`
}

func toGoose(g *trace.GooseStream) gooseJSON {
	issues := maps.Clone(g.Issues)
	if issues == nil {
		issues = map[string]int{}
	}
	return gooseJSON{Src: g.Src, Dst: g.Dst, AppID: g.AppID, VLAN: g.VLAN, GocbRef: g.GocbRef, DatSet: g.DatSet, GoID: g.GoID,
		ConfRev: g.ConfRev, Messages: g.Messages, Changes: g.Changes, Simulation: g.Simulation, NdsCom: g.NdsCom,
		MaxPerSecond: g.MaxPerSecond, First: jsonTime(g.FirstNS), Last: jsonTime(g.LastNS), Issues: issues}
}

// svJSON is one Sampled Values stream.
type svJSON struct {
	Src      string         `json:"src"`
	Dst      string         `json:"dst"`
	AppID    uint16         `json:"app_id"`
	VLAN     int            `json:"vlan"`
	SvID     string         `json:"sv_id"`
	DatSet   string         `json:"dat_set"`
	ConfRev  uint32         `json:"conf_rev"`
	Messages int            `json:"messages"`
	ASDUs    int            `json:"asdus"`
	Lost     int            `json:"lost"`
	Repeated int            `json:"repeated"`
	Wrap     int            `json:"wrap"`
	First    string         `json:"first,omitempty"`
	Last     string         `json:"last,omitempty"`
	Issues   map[string]int `json:"issues"`
}

type svStreamsJSON struct {
	fileHeader
	Streams []svJSON `json:"streams"`
}

func toSV(s *trace.SVStream) svJSON {
	issues := map[string]int{}
	if s.Lost > 0 {
		issues["lost"] = s.Lost
	}
	if s.Repeated > 0 {
		issues["repeated"] = s.Repeated
	}
	return svJSON{Src: s.Src, Dst: s.Dst, AppID: s.AppID, VLAN: s.VLAN, SvID: s.SvID, DatSet: s.DatSet, ConfRev: s.ConfRev,
		Messages: s.Messages, ASDUs: s.ASDUs, Lost: s.Lost, Repeated: s.Repeated, Wrap: s.Wrap,
		First: jsonTime(s.FirstNS), Last: jsonTime(s.LastNS), Issues: issues}
}

// objectName writes an object name: "LD0/MMXU1$MX$Hz" for a domain-specific
// name, "@/name" for an association-specific one, the item alone for a VMD
// name.
func objectName(n mms.ObjectName) string {
	switch n.Scope {
	case mms.ObjectScopeDomain:
		return string(n.Domain) + "/" + string(n.ItemID)
	case mms.ObjectScopeAssociation:
		return "@/" + string(n.ItemID)
	default:
		return string(n.ItemID)
	}
}

// object is a short summary of what a transaction is about: the first
// variable (and how many more), a variable list, the domain of a name
// list, or the identity an Identify returned.
func object(t *trace.Transaction) string {
	p := t.Request
	if p == nil {
		p = t.Response
	}
	if p == nil {
		return ""
	}
	switch {
	case len(p.Variables) > 0:
		s := objectName(p.Variables[0].Name)
		if n := len(p.Variables) - 1; n > 0 {
			s += fmt.Sprintf(" (+%d)", n)
		}
		return s
	case p.ListName != nil:
		return "list " + objectName(*p.ListName)
	case p.VariableName != nil:
		return objectName(*p.VariableName)
	case p.NameListRequest != nil:
		r := p.NameListRequest
		if r.Scope == mms.ObjectScopeDomain {
			return fmt.Sprintf("class %d in %s", r.ObjectClass, r.Domain)
		}
		return fmt.Sprintf("class %d (%s)", r.ObjectClass, r.Scope)
	}
	if r := t.Response; r != nil && r.Identify != nil {
		return strings.Join([]string{r.Identify.Vendor, r.Identify.Model, r.Identify.Revision}, " ")
	}
	return ""
}

// jsonTime is a capture time as RFC 3339 with nanoseconds, UTC, or "" for
// no time.
func jsonTime(ns int64) string {
	if ns == 0 {
		return ""
	}
	return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
}

// textTime is a capture time with microseconds, UTC, or "-".
func textTime(ns int64) string {
	if ns == 0 {
		return "-"
	}
	return time.Unix(0, ns).UTC().Format("2006-01-02T15:04:05.000000Z")
}

// csvTime is a capture time with nanoseconds, UTC, fixed width, or "".
func csvTime(ns int64) string {
	if ns == 0 {
		return ""
	}
	return time.Unix(0, ns).UTC().Format("2006-01-02T15:04:05.000000000Z")
}
