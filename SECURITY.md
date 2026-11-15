# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in go-mms-trace or `mmstracectl`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-mms-trace/security) tab → **Advisories** → **Report a vulnerability**), with:

- A description of the vulnerability
- Steps to reproduce the issue (a synthetic capture if you can; never send a customer's capture)
- The affected version(s) (`mmstracectl version` output)
- Any potential impact you've identified

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Security Considerations

### Captures are untrusted input

A capture can come from anywhere, so no reader or decoder trusts what it says. Every length is bounded before it is used, and so are the input as a whole and the work a packet costs ([ARCHITECTURE.md](ARCHITECTURE.md#2-limits) has the table and the reason for each default):

- the capture read at most 16 GiB, counted after decompression (`Options.MaxBytes`);
- a packet record at most 256 KiB (`Options.MaxPacket`), a pcapng block at most 16 MiB, a pcapng options area at most 64 KiB; a record or block is read in steps, so a length the input does not hold is not allocated;
- at most 65,536 pcapng interfaces and 65,536 sections (`Options.MaxInterfaces`, `Options.MaxSections`) and 16 MiB of their option text;
- IP fragment reassembly at most 1 MiB in total, at most 8 IPv6 extension headers; every fragment of a datagram lies within the length its last fragment gives;
- at most 100 000 tracked TCP connections and 64 MiB of out-of-order bytes (1 MiB per direction); sequence numbers are compared as the 32-bit numbers they are on every platform;
- a TPKT at most 65 535 bytes by its format, a reassembled TSDU at most 16 MiB (`MaxTSDU`), and 64 MiB of incomplete frames and TSDUs over all connections (`Options.MaxAssembly`);
- the work per packet does not grow with the number of connections tracked.

A packet that does not decode is counted, never an error; only a damaged file (`ErrCorrupt`) or a limit on the input as a whole (`ErrLimit`) ends the read. Each limit has a test that measures memory or work against it, and each stage has a fuzz target: the pcap and pcapng readers, the link parser, IP fragment reassembly and TCP reassembly with sequences of fragments and segments, the ISO framing with pieces, holes and other bytes, and `trace.Analyze` as a whole (`make fuzz`, 30 s per target in CI on pull requests, 5 minutes per target every night; [TESTING.md](TESTING.md)).

**The result grows with the capture.** The pipeline's buffers are bounded, but the result holds every transaction with its decoded PDUs, every report and every stream: up to about 30 bytes of memory for each byte of capture read. Measured on darwin/arm64 with Go 1.27.4 on 2026-11-14: 28 bytes per byte for a capture of the shortest confirmed request there is (an Identify request without session and presentation layers, 14 bytes with its TPKT and COTP headers, 100 to a TCP segment: 410 bytes for each transaction), and 8.4 bytes per byte for Read requests with all layers, 24 to a segment (`TestMaxBytes`). An application that analyses captures it does not trust sets `Options.MaxBytes` to what it can afford: memory of about 30 times that value, plus about 270 MiB for the pipeline when every one of its limits is reached ([ARCHITECTURE.md](ARCHITECTURE.md#2-limits)).

**The size of a gzip file bounds nothing.** Repeated traffic compresses about eightyfold (the two captures above: 4.2 MiB as 55 KiB, 8.3 MiB as 111 KiB), so the size of a compressed file says little about the capture in it. `Options.MaxBytes` counts the bytes after decompression, and `Analyze` reads no further: bounding the size of the file handed to `Analyze` is not a substitute for it. `File.UncompressedBytes` reports what was read.

### Names of a capture in the output

Names in a capture (object names, domains, GOOSE and SV references, the strings of an Identify response) are bytes the capture's source chose. `mmstracectl` writes every control character of such a string (the C0 set, DEL, the C1 set) and every byte that is not UTF-8 as `\xNN` in text and CSV output, and as a `\u` escape in JSON, so that a name is one cell of one row and no control sequence reaches the terminal. A CSV cell is written as it is when it starts with `=`, `+`, `-` or `@`: a spreadsheet that opens the file may read such a cell as a formula, so import the CSV as text where that matters. An application that shows strings of a `Result` does its own escaping: the library returns them as decoded.

### Credentials are never decoded

The AARQ's authentication mechanism is reported (`none`, `password`, `other`); the authentication value (a password) is never decoded, stored or printed.

### Offline only

The library never captures live, never opens a socket and never runs another program (`depguard` and `forbidigo` in `.golangci.yml` reject such imports and calls outside tests). `mmstracectl` reads files or standard input and writes standard output and standard error; nothing else.

### Captures contain sensitive data

A capture of a substation network reveals its devices, addresses, object names and process values, and the CLI's output repeats them. Handle the output like the capture.
