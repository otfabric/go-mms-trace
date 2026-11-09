// SPDX-License-Identifier: MIT

package trace

import (
	"net/netip"

	mms "github.com/otfabric/go-mms"
)

// Result is what a trace holds: the file, the MMS associations with their
// transactions and reports, and the GOOSE and Sampled Values streams.
type Result struct {
	File         File
	Associations []*Association
	// Transactions are the confirmed services of every association, in
	// the order their first PDU was captured.
	Transactions []*Transaction
	// Reports are the unconfirmed InformationReports, in capture order.
	Reports []*Report
	GOOSE   []*GooseStream
	SV      []*SVStream
	// Counters count what could not be used, by reason.
	Counters Counters
}

// File describes the capture file.
type File struct {
	Format string // "pcap" or "pcapng"
	Gzip   bool
	// SHA256 is the hex SHA-256 of the input as read (the compressed
	// bytes for gzip).
	SHA256     string
	Packets    uint64
	Interfaces int
	// Links are the link-layer names of the interfaces, in order
	// ("ethernet", "linux_sll", ...).
	Links []string
	// InputBytes is the size of the file as read (before decompression).
	InputBytes int64
	// TruncatedTail says the last record was cut short: the file ends in
	// the middle of a packet, which is dropped without an error. A read
	// error of the input is not truncation: it wraps ErrCorrupt.
	TruncatedTail bool
	// SkippedBlocks counts damaged pcapng blocks with a plausible length
	// that were skipped.
	SkippedBlocks uint64
	// FirstNS and LastNS are the times of the first and last packet,
	// Unix nanoseconds.
	FirstNS, LastNS int64
}

// Counters count frames and units the analysis could not use, and why.
type Counters struct {
	// Packets by link-layer outcome: not IP, not TCP, short, ...
	Unsupported map[string]uint64
	// TPKTResync counts bytes skipped to find the next TPKT header after
	// a gap or garbage.
	TPKTResync uint64
	// COTPErrors counts TPDUs that did not decode, TSDUErrors TSDUs that
	// did not decode (session, presentation, ACSE or MMS) or exceeded
	// MaxTSDU.
	COTPErrors, TSDUErrors uint64
	// BareMMS counts MMS PDUs carried straight in COTP, without the
	// session and presentation layers (not IEC 61850-8-1; some tools send
	// them). They are decoded and paired like the others.
	BareMMS uint64
	// TSOSegments counts IPv4 packets with a total length of 0, captured
	// on the sending host before segmentation offload filled it in; they
	// are used at their captured length.
	TSOSegments uint64
	// GOOSEErrors and SVErrors count frames with the EtherType that did
	// not decode.
	GOOSEErrors, SVErrors uint64
}

// Association is one MMS association: a TCP connection (or the part of it
// the capture holds) on which the ISO stack carried MMS.
type Association struct {
	ID int
	// Server is the end on an MMS port (Options.Ports), Client the other.
	Client, Server netip.AddrPort
	// Open says how it was first seen: "associate" (AARQ captured),
	// "connect" (COTP CR captured, no AARQ) or "midstream".
	Open string
	// Close says how it ended: "conclude", "release", "abort",
	// "disconnect" (COTP DR or DC, or TCP FIN in both directions, without
	// MMS conclude), "reset" (TCP RST) or "" (not seen ending: still open
	// at the end of the trace, evicted or superseded).
	Close string
	// Accepted is the AARE's result: nil when not captured.
	Accepted *bool
	// Authentication is the AARQ's mechanism ("none", "password",
	// "other"); credentials are never decoded.
	Authentication string
	// Initiate is the negotiated Initiate response, when captured.
	Initiate *mms.CapturedInitiate
	// TSAPs from the COTP connection request, when captured.
	CallingTSAP, CalledTSAP []byte

	FirstNS, LastNS int64
	Transactions    int
	Reports         int
	Unanswered      int
	// Gaps counts skipped ranges of either direction's byte stream (not
	// captured, cut by the snap length, or dropped by a reassembly
	// limit); an MMS PDU in a skipped range is not seen.
	Gaps int
}

// Status of a transaction.
const (
	StatusOK         = "ok"
	StatusError      = "error"      // a confirmed error
	StatusReject     = "reject"     // a reject PDU naming the invoke ID
	StatusUnanswered = "unanswered" // no response before the association ended or the invoke ID was reused
	StatusOrphan     = "orphan"     // a response whose request was not captured
	StatusPending    = "pending"    // no response before the capture ended
)

// Transaction is a confirmed service: the request and what answered it.
type Transaction struct {
	Association int
	InvokeID    uint32
	Service     string
	Status      string
	// ServerRequest marks a request the server sent (the file services a
	// server runs for ObtainFile, against the client's file store).
	ServerRequest bool
	Request       *mms.CapturedPDU
	// Response is the confirmed response, confirmed error or reject.
	Response *mms.CapturedPDU
	// RequestNS and ResponseNS are capture times (0 when not captured);
	// the frames are packet numbers in the file, from 1.
	RequestNS, ResponseNS       int64
	RequestFrame, ResponseFrame uint64
}

// LatencyNS is the time from request to response, or -1.
func (t *Transaction) LatencyNS() int64 {
	if t.RequestNS == 0 || t.ResponseNS == 0 {
		return -1
	}
	return t.ResponseNS - t.RequestNS
}

// Report is an unconfirmed InformationReport (an IEC 61850 report).
type Report struct {
	Association int
	TimeNS      int64
	Frame       uint64
	PDU         *mms.CapturedPDU
}
