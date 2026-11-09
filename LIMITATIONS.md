# Limitations

What go-mms-trace does not do, or has not proven yet.

## Decoding

- **MMS over TLS is not decodable.** IEC 62351-4 secures MMS with TLS (usually on TCP port 3782); the capture holds ciphertext. Adding 3782 to `Options.Ports` creates associations for those connections, but their TPDUs do not decode and are counted (`TPKTResync`, `COTPErrors`).
- **Only TCP port 102 by default.** MMS on another port is found only when that port is given in `Options.Ports` (`mmstracectl --port`). There is no detection by content.
- **What go-mms decodes is what is shown.** Services that go-mms's `DecodeTSDU` does not model keep their raw content in `mms.CapturedPDU.Raw`; a modelled service that fails to decode has `DecodeError` set. The library adds no decoding of its own above COTP.
- **Authentication values are never decoded**, only the mechanism (`none`, `password`, `other`).
- **One association per TCP connection.** A new AARQ on the same connection after a release is counted in the same association.
- **GOOSE and SV only on Ethernet link types.** Frames in Linux cooked captures (SLL, SLL2) are not searched for the GOOSE and SV EtherTypes; routable GOOSE and SV (IEC 61850-90-5, over UDP) are not decoded.
- **Sampled Values sequencing is per stream and in capture order**; a counter wrap is assumed when smpCnt falls, so a large loss right before a wrap is not counted.

## Memory

`Analyze` returns the whole result: every transaction with its decoded PDUs, every report, and per GOOSE stream the set of (stNum, sqNum) pairs seen. The buffers of the pipeline are bounded ([ARCHITECTURE.md](ARCHITECTURE.md) section 2), but the result grows with the capture. There is no streaming API yet.

## Evidence

- **Few captures of real devices.** Besides the generated fixtures and the captures between independent stacks (`testdata/captures/interop`), the public captures include MMS sessions with ABB and Siemens IEDs and an OMICRON IEDScout session of unknown origin and date (`testdata/captures/public`, ICS-Pcaps); every MMS PDU of all of them matches Wireshark's dissector. Captures of current devices with documented firmware are still to be added.
- **No comparison with Wireshark's dissector yet.**

## Dependencies

- go-iec61850's `goose` and `sv` packages implement live capture as well as decoding, so this module links `golang.org/x/sys/unix` through them, although it only calls `goose.Decode` and `sv.Decode`. A decode-only split of those packages is a go-iec61850 follow-up.
