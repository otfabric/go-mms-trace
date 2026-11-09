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

A capture can come from anywhere, so every reader and decoder treats it as hostile. Every length is bounded before it is used:

- a packet record at most 256 KiB (`Options.MaxPacket`), a pcapng block at most 16 MiB, a pcapng options area at most 64 KiB;
- IP fragment reassembly at most 1 MiB in total, at most 8 IPv6 extension headers;
- at most 100 000 tracked TCP connections and 64 MiB of out-of-order bytes (1 MiB per direction);
- a TPKT at most 65 535 bytes by its format, a reassembled TSDU at most 16 MiB (`MaxTSDU`).

A packet that does not decode is counted, never an error; only a damaged file ends the read (`ErrCorrupt`). The pcap and pcapng readers, the link parser and `trace.Analyze` are fuzzed (`make fuzz`, and 30 s per target in CI). TCP reassembly is fuzzed only through `trace.Analyze`.

The result itself is not bounded: it grows with the number of transactions, reports and GOOSE messages in the capture ([LIMITATIONS.md](LIMITATIONS.md#memory)). An application that analyses captures from untrusted sources should bound the input size it accepts.

### Credentials are never decoded

The AARQ's authentication mechanism is reported (`none`, `password`, `other`); the authentication value (a password) is never decoded, stored or printed.

### Offline only

The library never captures live, never opens a socket and never runs another program (`depguard` and `forbidigo` in `.golangci.yml` reject such imports and calls outside tests). `mmstracectl` reads files or standard input and writes standard output and standard error; nothing else.

### Captures contain sensitive data

A capture of a substation network reveals its devices, addresses, object names and process values, and the CLI's output repeats them. Handle the output like the capture.
