# Exit codes

`mmstracectl` uses the organisation exit-code table (otfabric engineering, `standards/api-design.md`, CLI-001). It reads files only, so it has no transport, timeout, protocol, permission or safety codes, and no command completes with a result that reports problems, so 1 (findings) is not used:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 2 | Usage: an unknown command or flag, a wrong number of arguments, a bad flag value (also from an `MMSTRACECTL_*` variable), a format the command does not write, standard input combined with other captures. |
| 3 | Invalid input: a capture that cannot be opened, is not a pcap or pcapng file (also an invalid gzip header), is damaged, or goes on past a limit (`--max-bytes`, or 65,536 pcapng sections). For a damaged capture and for one past a limit, the command first prints what was read of it (in JSON with an `error` field), then the error goes to stderr; with several such captures, stderr names the first. |
| 10 | Output or internal error: an output that cannot be written (a closed pipe, a full disk), or a bug. |
| 130 | Interrupted: Ctrl-C (SIGINT) or SIGTERM stops the analysis between packets; a command interrupted while reading writes nothing to stdout. |

A capture that cannot be opened or is not a capture fails the command before anything is written. A read error after a capture's file header, and a gzip capture whose checksum does not match, are damage: the command prints what was read before it and exits 3. A capture larger than `--max-bytes` (16 GiB after decompression by default) is not damaged, and is reported the same way: what was read up to the limit, then exit 3; a higher `--max-bytes` reads it whole. A last record cut short is not an error (`truncated_tail`). Errors go to stderr as text, also with `--format json`.
