# JSON output

`--format json` (or `MMSTRACECTL_FORMAT=json`) makes `mmstracectl` write one indented JSON document to stdout. Every document but `version`'s is

```json
{"schema_version": 1, "files": [ ... ]}
```

with one object per capture, in argument order. Each starts with `file` (the argument as given, `-` for standard input) and, for a damaged capture, `error` (what ended the read; the rest is what was read before it). Field names are snake_case and stable; a change is called out in the release notes. Times are RFC 3339 with nanoseconds, UTC, and absent when the capture has no time. Endpoints are `ip:port` (IPv6 in brackets).

## `info`

```json
{
  "file": "substation.pcap", "format": "pcap", "gzip": false, "sha256": "...", "input_bytes": 6768,
  "packets": 61, "interfaces": 1, "links": ["ethernet"],
  "first": "2026-11-09T12:00:00.001Z", "last": "2026-11-09T12:00:00.061Z",
  "truncated_tail": false, "skipped_blocks": 0,
  "associations": 4, "transactions": 9,
  "statuses": {"ok": 5, "error": 1, "unanswered": 1, "orphan": 1, "pending": 1},
  "reports": 1, "goose_streams": 1, "sv_streams": 1,
  "counters": {"tpkt_resync": 0, "cotp_errors": 0, "tsdu_errors": 0, "bare_mms": 0, "tso_segments": 0, "goose_errors": 0, "sv_errors": 0},
  "services": {"Read": 5, "Write": 1},
  "unsupported": {"other_tcp": 1}
}
```

`statuses` and `services` count the transactions; `unsupported` counts packets without a usable TCP segment by reason, and `other_tcp` segments on other ports. The counters are explained in [ERRORS.md](../../../ERRORS.md).

## `associations`

```json
{"file": "...", "associations": [{
  "id": 1, "client": "10.0.0.1:40000", "server": "10.0.0.2:102",
  "open": "associate", "close": "conclude", "accepted": true, "authentication": "none",
  "calling_tsap": "0001", "called_tsap": "0001",
  "transactions": 5, "reports": 0, "unanswered": 0, "gaps": 0,
  "first": "...", "last": "..."
}]}
```

`open` is `associate`, `connect` or `midstream`; `close` is `conclude`, `release`, `abort`, `disconnect`, `reset` or `""` (open at the end of the capture). `accepted` is `null` when no AARE was captured. `authentication` is `none`, `password`, `other` or `""` (no AARQ captured). The TSAPs are hex, `""` without a COTP CR.

## `transactions`

```json
{"file": "...", "transactions": [{
  "time": "...", "association": 1, "invoke_id": 5, "service": "FileDelete", "status": "error",
  "latency_ms": 1, "object": "", "request_frame": 19, "response_frame": 20,
  "error": {"class": 0, "code": 4}
}]}
```

In time order: `time` is the request's, or the response's when the request was not captured. `status` is `ok`, `error`, `reject`, `unanswered`, `orphan` or `pending`. `latency_ms` is `null` without both times. `request_frame` and `response_frame` are packet numbers from 1, absent when not captured. `error` (class and code of a confirmed error) and `reject` (`type` and `reason` of a reject PDU) are present only then. `object` is described in the [README](../README.md#output).

## `reports`

```json
{"file": "...", "reports": [{
  "time": "...", "association": 2, "frame": 36, "variables": ["LD0/LLN0$RP$urcb"], "values": 1
}]}
```

`list_name` is the named variable list a report names (absent otherwise), `variables` the variables it names, `values` the number of access results.

## `goose`

```json
{"file": "...", "streams": [{
  "src": "02:00:00:00:00:09", "dst": "01:0c:cd:01:00:01", "app_id": 1, "vlan": -1,
  "gocb_ref": "IED1LD0/LLN0$GO$gcb1", "dat_set": "IED1LD0/LLN0$ds1", "go_id": "gcb1", "conf_rev": 1,
  "messages": 6, "changes": 2, "simulation": 0, "nds_com": 0, "max_per_second": 6,
  "first": "...", "last": "...",
  "issues": {"repeated (stNum, sqNum)": 1, "stNum jumped": 1}
}]}
```

`vlan` is -1 when untagged. `changes` counts stNum increments; `simulation` and `nds_com` count messages with those flags; `max_per_second` is the most messages in one second of capture time. `issues` counts by kind: `stNum decreased`, `stNum jumped`, `sqNum gap`, `repeated (stNum, sqNum)`, `confRev changed`, `entries changed`.

## `sv`

```json
{"file": "...", "streams": [{
  "src": "02:00:00:00:00:08", "dst": "01:0c:cd:04:00:01", "app_id": 16384, "vlan": -1,
  "sv_id": "MU01", "dat_set": "", "conf_rev": 1, "messages": 5, "asdus": 5,
  "lost": 2, "repeated": 1, "wrap": 6, "first": "...", "last": "...",
  "issues": {"lost": 2, "repeated": 1}
}]}
```

`asdus` counts samples; `lost` counts smpCnt values skipped, `repeated` those seen twice in a row; `wrap` is the highest smpCnt seen plus one. `issues` repeats `lost` and `repeated` when they are not zero.

## `version`

One line, the organisation's version document:

```json
{"name":"mmstracectl","version":"0.1.0","tag":"v0.1.0","commit":"...","built":"...","libraries":[{"name":"go-mms","version":"1.6.0"}],"go":"go1.26.0","platform":"linux/amd64"}
```

`libraries` are the OT Fabric libraries the binary is built on (without go-mms-trace itself).
