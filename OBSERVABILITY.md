# Observability

## Logs and hooks

The library writes no logs and has no metrics hooks, callbacks or progress reports: `trace.Analyze` runs to the end of the input (or the cancellation of its context) and returns everything it observed in the `Result`. It imports no logging package.

## Stats fields

What the analysis observed about its own input, besides the decoded traffic:

| Where | Fields | Documented in |
|---|---|---|
| `Result.File` | `Packets`, `InputBytes`, `SHA256`, `TruncatedTail`, `SkippedBlocks`, `Interfaces`, `Links`, `FirstNS`, `LastNS` | [API.md](API.md#file) |
| `Result.Counters` | `Unsupported` by reason, `TPKTResync`, `COTPErrors`, `TSDUErrors`, `BareMMS`, `TSOSegments`, `GOOSEErrors`, `SVErrors` | [ERRORS.md](ERRORS.md#counters) |
| `Association` | `Gaps`, `Unanswered`, `Open` (`midstream` when the start was not captured), `Close` (empty when the end was not seen) | [API.md](API.md#association) |
| `Transaction.Status` | `unanswered`, `orphan`, `pending` | [API.md](API.md#transaction) |
| `mms.CapturedPDU.DecodeError` | a PDU whose service content did not decode | [API.md](API.md#report) |
| `GooseStream.Issues`, `SVStream.Lost`, `SVStream.Repeated` | sequencing anomalies of the publishers | [API.md](API.md#goosestream) |

Every counter is cumulative over one `Analyze` call; nothing is kept between calls. Counter keys and status values are fixed strings, so they are safe as metric labels.

What the pipeline tracks internally but does not report (TCP retransmissions and overlaps, IP fragments dropped by the reassembly budget, pcapng option errors and unknown blocks) is listed in [LIMITATIONS.md](LIMITATIONS.md#capture-files).

## mmstracectl

`mmstracectl info` prints the `File` fields and every counter of each capture (text or JSON, [cmd/mmstracectl/docs/json-output.md](cmd/mmstracectl/docs/json-output.md#info)); `associations` prints gaps and unanswered requests per association. Errors go to standard error as one `mmstracectl: ...` line (a usage error adds a line pointing to `--help`), and the exit code says what kind of failure it was ([cmd/mmstracectl/docs/exitcodes.md](cmd/mmstracectl/docs/exitcodes.md)). The CLI has no verbose or debug mode.
