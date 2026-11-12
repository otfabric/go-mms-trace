# go-mms-trace: agent handoff

This file is the entry point for Claude Code and other agents. Read it fully, then the documents it points to, before writing code.

## What this is

A pure-Go library and CLI that read **packet captures** (pcap and pcapng, plain or gzip) of IEC 61850 traffic and report what they hold: the MMS associations over ISO-on-TCP with their confirmed services paired by invoke ID and their InformationReports, and the GOOSE and Sampled Values streams. It never captures live and never sends anything: the capture is its only input. It is meant as the trace engine of the IEC 61850 Explorer and as the headless `mmstracectl`.

## Organisation standards

This repository follows **otfabric/engineering policy 1.5**, profile **protocol-library** (`.otfabric/policy.yaml`); CI runs otfabric-policy v1.5.0. Organisation skills come from the `otfabric` plugin. There are no local exceptions (no `.otfabric/exceptions.yaml`). Where this file and the organisation standards disagree, this file wins for this repository — say so in your report.

## Read these, in this order

1. [ARCHITECTURE.md](ARCHITECTURE.md): the pipeline, the limits, how associations and pairing work.
2. [API.md](API.md): the `trace` package.
3. [LIMITATIONS.md](LIMITATIONS.md): what is not decoded or not proven.
4. [TESTING.md](TESTING.md): how captures are generated, fixtures, golden files, fuzzing.
5. [INTEROPERABILITY.md](INTEROPERABILITY.md) and [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md): the captures of other implementations, the Wireshark comparison, the evidence per feature.
6. [cmd/mmstracectl/README.md](cmd/mmstracectl/README.md) and its `docs/`: the CLI, its JSON output and exit codes.

## Decisions that are settled

- **Offline only.** The library never opens a network socket, never captures live, never runs a program. Enforced by `depguard` and `forbidigo` in `.golangci.yml` (tests may run go-mms over TCP on 127.0.0.1).
- **Pure Go, `CGO_ENABLED=0`**, on linux/amd64, linux/arm64, linux/arm (v7), darwin/arm64, darwin/amd64, windows/amd64, windows/arm64.
- **Decoding belongs to the protocol libraries.** MMS (session, presentation, ACSE, MMS PDUs) through go-mms `mms.DecodeTSDU`, COTP through go-cotp, GOOSE and SV through go-iec61850. A decoding gap is fixed there, not here.
- **Reader, link parsing and TCP reassembly are our own**, adapted from go-modbus-trace (`internal/pcapio`, `internal/link`, `internal/flow`); no gopacket.
- **The only clock is the capture's timestamps.** No `time.Now` in the library.
- **Untrusted input.** Every length is bounded, the readers, the link parser and `Analyze` are fuzzed, a packet that does not decode is counted, never a panic or an error. The `Result` itself is not bounded.
- **Credentials are never decoded**: only the authentication mechanism.
- **The CLI is a nested module** (`cmd/mmstracectl`, its own `go.mod`), so the library does not depend on cobra. It pins a released version of the library; a `go.work` (git-ignored) joins them during development.

## Hard rules

- No `panic` across the public API.
- Never ship customer captures. Captures are generated (`make golden`, [TESTING.md](TESTING.md)), recorded between the independent stacks of iec61850-interop (`scripts/record-interop.sh`), or public captures with source, licence and checksum in `testdata/captures/public/manifest.json` ([INTEROPERABILITY.md](INTEROPERABILITY.md)).
- SPDX header `// SPDX-License-Identifier: MIT` on every Go file; MIT license.
- JSON output of the CLI uses its own output types (snake_case), never the library's structs marshalled directly.
- Do not commit unless the user asks.

## Definition of done for any change

`make check` passes; new behaviour has a test on a generated capture; a new counter or status is documented in [ERRORS.md](ERRORS.md) or [API.md](API.md), and a new or changed capability in [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md); a change to the CLI's output updates the golden files (`make golden`) and `cmd/mmstracectl/docs/json-output.md`.
