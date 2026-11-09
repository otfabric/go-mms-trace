// SPDX-License-Identifier: MIT

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/otfabric/go-mms-trace/trace"
)

// statuses are the transaction statuses, in the order they are listed.
var statuses = []string{trace.StatusOK, trace.StatusError, trace.StatusReject, trace.StatusUnanswered,
	trace.StatusOrphan, trace.StatusPending}

// writer is how a command writes its result in one format.
type writer func(w io.Writer, as []analysis, format string) error

// captureCommand is a command that analyses captures and writes the result
// in one of formats (the first is the default).
func captureCommand(e *env, use, short, long string, formats []string, write writer) (*cobra.Command, *analysisFlags) {
	var f analysisFlags
	var format string
	c := &cobra.Command{
		Use:   use + " CAPTURE...",
		Short: short,
		Long:  long,
		Args:  args(1, -1),
		RunE: func(cmd *cobra.Command, names []string) error {
			as, err := load(cmd.Context(), e, names, &f)
			if err != nil {
				return err
			}
			if err := write(e.stdout, as, format); err != nil {
				return err
			}
			return damaged(as)
		},
	}
	f.add(c)
	formatFlag(c, &format, formats...)
	return c, &f
}

func infoCommand(e *env) *cobra.Command {
	c, _ := captureCommand(e, "info", "Summarise each capture: file, MMS, GOOSE and SV counts, counters",
		`Summarise each capture: its format, size, SHA-256, packets, interfaces and time
span; the number of associations, transactions by status and service, reports,
GOOSE and SV streams; and the counters of what could not be used.`,
		[]string{formatText, formatJSON}, writeInfo)
	return c
}

func writeInfo(w io.Writer, as []analysis, format string) error {
	if format == formatJSON {
		doc := document[infoJSON]{SchemaVersion: schemaVersion, Files: []infoJSON{}}
		for _, a := range as {
			doc.Files = append(doc.Files, toInfo(a))
		}
		return writeJSON(w, doc)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, a := range as {
		x := toInfo(a)
		if i > 0 {
			_, _ = fmt.Fprintln(tw)
		}
		gz := ""
		if x.Gzip {
			gz = ", gzip"
		}
		lines := [][2]string{
			{"file", x.File},
			{"format", fmt.Sprintf("%s%s, %d bytes, %d packets", x.Format, gz, x.InputBytes, x.Packets)},
			{"interfaces", fmt.Sprintf("%d (%s)", x.Interfaces, strings.Join(x.Links, ", "))},
			{"sha256", x.SHA256},
			{"first", textTime(a.res.File.FirstNS)},
			{"last", textTime(a.res.File.LastNS)},
			{"associations", strconv.Itoa(x.Associations)},
			{"transactions", fmt.Sprintf("%d (%s)", x.Transactions, statusText(x.Statuses))},
			{"services", countText(x.Services)},
			{"reports", strconv.Itoa(x.Reports)},
			{"goose streams", strconv.Itoa(x.GooseStreams)},
			{"sv streams", strconv.Itoa(x.SVStreams)},
			{"counters", fmt.Sprintf("tpkt_resync=%d, cotp_errors=%d, tsdu_errors=%d, bare_mms=%d, tso_segments=%d, goose_errors=%d, sv_errors=%d",
				x.Counters.TPKTResync, x.Counters.COTPErrors, x.Counters.TSDUErrors, x.Counters.BareMMS, x.Counters.TSOSegments,
				x.Counters.GOOSEErrors, x.Counters.SVErrors)},
			{"unsupported", countText(x.Unsupported)},
		}
		if x.TruncatedTail {
			lines = append(lines, [2]string{"truncated", "the last record was cut short"})
		}
		if x.SkippedBlocks > 0 {
			lines = append(lines, [2]string{"skipped blocks", strconv.FormatUint(x.SkippedBlocks, 10)})
		}
		if x.Error != "" {
			lines = append(lines, [2]string{"error", x.Error})
		}
		for _, l := range lines {
			_, _ = fmt.Fprintf(tw, "%s\t%s\n", l[0], l[1])
		}
	}
	return tw.Flush()
}

// statusText lists the statuses with a count, in the order of statuses.
func statusText(m map[string]int) string {
	var parts []string
	for _, s := range statuses {
		if m[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", s, m[s]))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// countText writes a count map as "key=n, key=n" in key order, or "-".
func countText[N int | uint64](m map[string]N) string {
	if len(m) == 0 {
		return "-"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func associationsCommand(e *env) *cobra.Command {
	c, _ := captureCommand(e, "associations", "List the MMS associations",
		`List the MMS associations, one row each: ID, client and server endpoints, how it
was opened (associate, connect, midstream) and closed (conclude, release, abort,
disconnect, reset, or open at the end of the capture), whether the AARE accepted
it, the authentication mechanism of the AARQ, the counts of transactions,
reports, unanswered requests and gaps, and the first and last time.`,
		[]string{formatText, formatJSON}, writeAssociations)
	c.Aliases = []string{"assoc"}
	return c
}

func writeAssociations(w io.Writer, as []analysis, format string) error {
	if format == formatJSON {
		doc := document[associationsJSON]{SchemaVersion: schemaVersion, Files: []associationsJSON{}}
		for _, a := range as {
			x := associationsJSON{fileHeader: header(a), Associations: []associationJSON{}}
			for _, s := range a.res.Associations {
				x.Associations = append(x.Associations, toAssociation(s))
			}
			doc.Files = append(doc.Files, x)
		}
		return writeJSON(w, doc)
	}
	return eachFile(w, as, func(tw io.Writer, a analysis) {
		_, _ = fmt.Fprintln(tw, "ID\tCLIENT\tSERVER\tOPEN\tCLOSE\tACCEPTED\tAUTH\tTXNS\tREPORTS\tUNANSWERED\tGAPS\tFIRST\tLAST")
		for _, s := range a.res.Associations {
			x := toAssociation(s)
			acc := "-"
			if x.Accepted != nil {
				acc = strconv.FormatBool(*x.Accepted)
			}
			_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", x.ID, x.Client, x.Server, x.Open,
				dash(x.Close), acc, dash(x.Authentication), x.Transactions, x.Reports, x.Unanswered, x.Gaps,
				textTime(s.FirstNS), textTime(s.LastNS))
		}
	})
}

// transactionFilter selects transactions.
type transactionFilter struct {
	services []string
	statuses []string
	assocs   []int
}

func (f *transactionFilter) check() error {
	for _, s := range f.statuses {
		if !slices.Contains(statuses, s) {
			return usageErr("--status %q: want %s", s, strings.Join(statuses, ", "))
		}
	}
	for _, a := range f.assocs {
		if a < 1 {
			return usageErr("--assoc %d: association IDs start at 1", a)
		}
	}
	return nil
}

func (f *transactionFilter) match(t *trace.Transaction) bool {
	if len(f.services) > 0 && !slices.ContainsFunc(f.services, func(s string) bool { return strings.EqualFold(s, t.Service) }) {
		return false
	}
	if len(f.statuses) > 0 && !slices.Contains(f.statuses, t.Status) {
		return false
	}
	return len(f.assocs) == 0 || slices.Contains(f.assocs, t.Association)
}

func transactionsCommand(e *env) *cobra.Command {
	var sel transactionFilter
	c, _ := captureCommand(e, "transactions", "List the confirmed services in time order",
		`List the confirmed services (transactions) in time order: the time of the
request (of the response when the request was not captured), association,
invoke ID, service, status (ok, error, reject, unanswered, orphan, pending),
latency in milliseconds and a short summary of the object.`,
		[]string{formatText, formatJSON, formatCSV}, func(w io.Writer, as []analysis, format string) error {
			return writeTransactions(w, as, format, &sel)
		})
	c.Aliases = []string{"timeline"}
	c.Flags().StringSliceVar(&sel.services, "service", nil, "only these services (Read, Write, GetNameList, ...; any case)")
	c.Flags().StringSliceVar(&sel.statuses, "status", nil, "only these statuses: "+strings.Join(statuses, ", "))
	c.Flags().IntSliceVar(&sel.assocs, "assoc", nil, "only these association IDs")
	_ = c.Flags().SetAnnotation("status", valuesAnnotation, statuses) // the flag exists
	c.PreRunE = chain(c.PreRunE, func(*cobra.Command, []string) error { return sel.check() })
	return c
}

func writeTransactions(w io.Writer, as []analysis, format string, sel *transactionFilter) error {
	selected := func(a analysis) []transactionJSON {
		out := []transactionJSON{}
		for _, t := range sortedTransactions(a.res.Transactions) {
			if sel.match(t) {
				out = append(out, toTransaction(t))
			}
		}
		return out
	}
	switch format {
	case formatJSON:
		doc := document[transactionsJSON]{SchemaVersion: schemaVersion, Files: []transactionsJSON{}}
		for _, a := range as {
			doc.Files = append(doc.Files, transactionsJSON{fileHeader: header(a), Transactions: selected(a)})
		}
		return writeJSON(w, doc)
	case formatCSV:
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"file", "time", "association", "invoke_id", "service", "status", "latency_ms", "object",
			"request_frame", "response_frame", "error_class", "error_code"})
		for _, a := range as {
			for _, t := range sortedTransactions(a.res.Transactions) {
				if !sel.match(t) {
					continue
				}
				x := toTransaction(t)
				ec, eco := "", ""
				if x.Error != nil {
					ec, eco = strconv.Itoa(x.Error.Class), strconv.Itoa(x.Error.Code)
				}
				_ = cw.Write([]string{a.name, csvTime(transactionTime(t)), strconv.Itoa(x.Association), strconv.FormatUint(uint64(x.InvokeID), 10),
					x.Service, x.Status, latency(x.LatencyMS, ""), x.Object, frame(x.RequestFrame), frame(x.ResponseFrame), ec, eco})
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return eachFile(w, as, func(tw io.Writer, a analysis) {
		_, _ = fmt.Fprintln(tw, "TIME\tASSOC\tINVOKE\tSERVICE\tSTATUS\tLATENCY_MS\tOBJECT")
		for _, t := range sortedTransactions(a.res.Transactions) {
			if !sel.match(t) {
				continue
			}
			x := toTransaction(t)
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n", textTime(transactionTime(t)), x.Association, x.InvokeID,
				dash(x.Service), x.Status, latency(x.LatencyMS, "-"), dash(x.Object))
		}
	})
}

func reportsCommand(e *env) *cobra.Command {
	c, _ := captureCommand(e, "reports", "List the InformationReports",
		`List the unconfirmed InformationReports (IEC 61850 reports) in capture order:
time, association, the named variable list or the variables they carry, and
the number of values.`,
		[]string{formatText, formatJSON, formatCSV}, writeReports)
	return c
}

func writeReports(w io.Writer, as []analysis, format string) error {
	switch format {
	case formatJSON:
		doc := document[reportsJSON]{SchemaVersion: schemaVersion, Files: []reportsJSON{}}
		for _, a := range as {
			x := reportsJSON{fileHeader: header(a), Reports: []reportJSON{}}
			for _, r := range a.res.Reports {
				x.Reports = append(x.Reports, toReport(r))
			}
			doc.Files = append(doc.Files, x)
		}
		return writeJSON(w, doc)
	case formatCSV:
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"file", "time", "association", "frame", "list_name", "variables", "values"})
		for _, a := range as {
			for _, r := range a.res.Reports {
				x := toReport(r)
				_ = cw.Write([]string{a.name, csvTime(r.TimeNS), strconv.Itoa(x.Association), frame(x.Frame), x.ListName,
					strings.Join(x.Variables, " "), strconv.Itoa(x.Values)})
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return eachFile(w, as, func(tw io.Writer, a analysis) {
		_, _ = fmt.Fprintln(tw, "TIME\tASSOC\tNAME\tVALUES")
		for _, r := range a.res.Reports {
			x := toReport(r)
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%d\n", textTime(r.TimeNS), x.Association, dash(reportName(x)), x.Values)
		}
	})
}

func gooseCommand(e *env) *cobra.Command {
	c, _ := captureCommand(e, "goose", "List the GOOSE streams with their issues",
		`List the GOOSE publishers (one stream per source MAC, APPID and GoCB reference):
addresses, VLAN, references, messages, state changes, flags and the sequencing
issues (stNum decreased or jumped, sqNum gap, repeated (stNum, sqNum), confRev
or entries changed).`,
		[]string{formatText, formatJSON, formatCSV}, writeGoose)
	return c
}

func writeGoose(w io.Writer, as []analysis, format string) error {
	switch format {
	case formatJSON:
		doc := document[gooseStreamsJSON]{SchemaVersion: schemaVersion, Files: []gooseStreamsJSON{}}
		for _, a := range as {
			x := gooseStreamsJSON{fileHeader: header(a), Streams: []gooseJSON{}}
			for _, g := range a.res.GOOSE {
				x.Streams = append(x.Streams, toGoose(g))
			}
			doc.Files = append(doc.Files, x)
		}
		return writeJSON(w, doc)
	case formatCSV:
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"file", "src", "dst", "app_id", "vlan", "gocb_ref", "dat_set", "go_id", "conf_rev", "messages",
			"changes", "simulation", "nds_com", "max_per_second", "first", "last", "issues"})
		for _, a := range as {
			for _, g := range a.res.GOOSE {
				x := toGoose(g)
				_ = cw.Write([]string{a.name, x.Src, x.Dst, appID(x.AppID), strconv.Itoa(x.VLAN), x.GocbRef, x.DatSet, x.GoID,
					strconv.FormatUint(uint64(x.ConfRev), 10), strconv.Itoa(x.Messages), strconv.Itoa(x.Changes),
					strconv.Itoa(x.Simulation), strconv.Itoa(x.NdsCom), strconv.Itoa(x.MaxPerSecond), csvTime(g.FirstNS), csvTime(g.LastNS), countText(x.Issues)})
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return eachFile(w, as, func(tw io.Writer, a analysis) {
		_, _ = fmt.Fprintln(tw, "SRC\tAPPID\tVLAN\tGOCBREF\tMESSAGES\tCHANGES\tMAX/S\tISSUES")
		for _, g := range a.res.GOOSE {
			x := toGoose(g)
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", x.Src, appID(x.AppID), vlan(x.VLAN), x.GocbRef,
				x.Messages, x.Changes, x.MaxPerSecond, countText(x.Issues))
		}
	})
}

func svCommand(e *env) *cobra.Command {
	c, _ := captureCommand(e, "sv", "List the Sampled Values streams with their issues",
		`List the Sampled Values publishers (one stream per source MAC, APPID and svID):
addresses, VLAN, svID, messages, ASDUs, samples lost and repeated (from smpCnt),
and the estimated counter wrap.`,
		[]string{formatText, formatJSON, formatCSV}, writeSV)
	return c
}

func writeSV(w io.Writer, as []analysis, format string) error {
	switch format {
	case formatJSON:
		doc := document[svStreamsJSON]{SchemaVersion: schemaVersion, Files: []svStreamsJSON{}}
		for _, a := range as {
			x := svStreamsJSON{fileHeader: header(a), Streams: []svJSON{}}
			for _, s := range a.res.SV {
				x.Streams = append(x.Streams, toSV(s))
			}
			doc.Files = append(doc.Files, x)
		}
		return writeJSON(w, doc)
	case formatCSV:
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"file", "src", "dst", "app_id", "vlan", "sv_id", "dat_set", "conf_rev", "messages", "asdus",
			"lost", "repeated", "wrap", "first", "last", "issues"})
		for _, a := range as {
			for _, s := range a.res.SV {
				x := toSV(s)
				_ = cw.Write([]string{a.name, x.Src, x.Dst, appID(x.AppID), strconv.Itoa(x.VLAN), x.SvID, x.DatSet,
					strconv.FormatUint(uint64(x.ConfRev), 10), strconv.Itoa(x.Messages), strconv.Itoa(x.ASDUs),
					strconv.Itoa(x.Lost), strconv.Itoa(x.Repeated), strconv.Itoa(x.Wrap), csvTime(s.FirstNS), csvTime(s.LastNS), countText(x.Issues)})
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return eachFile(w, as, func(tw io.Writer, a analysis) {
		_, _ = fmt.Fprintln(tw, "SRC\tAPPID\tVLAN\tSVID\tMESSAGES\tASDUS\tLOST\tREPEATED\tWRAP\tISSUES")
		for _, s := range a.res.SV {
			x := toSV(s)
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", x.Src, appID(x.AppID), vlan(x.VLAN), x.SvID,
				x.Messages, x.ASDUs, x.Lost, x.Repeated, x.Wrap, countText(x.Issues))
		}
	})
}

// eachFile writes a text table per capture through a tabwriter, with a
// "==> name <==" line before each when there are several.
func eachFile(w io.Writer, as []analysis, table func(io.Writer, analysis)) error {
	for i, a := range as {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if len(as) > 1 {
			if i > 0 {
				_, _ = fmt.Fprintln(tw)
			}
			_, _ = fmt.Fprintf(tw, "==> %s <==\n", a.name)
		}
		table(tw, a)
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// writeJSON writes one indented JSON document.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// chain runs the pre-run hooks in order.
func chain(fns ...func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, a []string) error {
		for _, fn := range fns {
			if fn == nil {
				continue
			}
			if err := fn(c, a); err != nil {
				return err
			}
		}
		return nil
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func latency(ms *float64, none string) string {
	if ms == nil {
		return none
	}
	return strconv.FormatFloat(*ms, 'f', 3, 64)
}

func frame(n uint64) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatUint(n, 10)
}

func appID(id uint16) string { return fmt.Sprintf("0x%04x", id) }

func vlan(v int) string {
	if v < 0 {
		return "-"
	}
	return strconv.Itoa(v)
}
