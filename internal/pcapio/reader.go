// SPDX-License-Identifier: MIT

// Package pcapio reads classic pcap and pcapng files, plain or gzip, from a
// file or a stream, and writes them. Every record carries its frame number
// and its offset in the uncompressed stream, so that a packet can be found
// again. The reader treats its input as hostile: every length is bounded,
// and a damaged pcapng block with a plausible length is skipped and counted.
// The bytes read from one input (after decompression) and the interfaces,
// sections and option text kept from it are limited, so what the reader does
// and holds does not grow without bound with what a small input declares or
// unpacks to.
//
// Adapted from go-modbus-trace internal/pcapio.
package pcapio

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/bits"
)

// Format is a trace file format.
type Format int

// Formats.
const (
	Pcap Format = iota + 1
	PcapNG
)

// String returns "pcap" or "pcapng".
func (f Format) String() string {
	switch f {
	case Pcap:
		return "pcap"
	case PcapNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// Errors.
var (
	// ErrFormat reports a stream that is neither pcap nor pcapng.
	ErrFormat = errors.New("trace: not a pcap or pcapng file")
	// ErrCorrupt reports damage that ends the read; the packets read so
	// far are valid.
	ErrCorrupt = errors.New("trace: corrupt trace file")
	// ErrLimit reports an input that goes on past Options.MaxBytes or has
	// more sections than Options.MaxSections: the read ends there, and the
	// packets read so far are valid.
	ErrLimit = errors.New("trace: capture beyond a limit")
)

// Default bounds.
const (
	DefaultMaxPacket = 256 << 10 // largest captured packet accepted
	DefaultMaxBlock  = 16 << 20  // largest pcapng block skipped over
	// DefaultMaxBytes is the number of bytes read from one input, counted
	// after decompression: 16 GiB. An hour of one Sampled Values stream at
	// 4800 frames a second is about 2.5 GiB, and capture tools rotate their
	// files well below this size.
	DefaultMaxBytes = 16 << 30
	// DefaultMaxInterfaces is the number of interfaces kept from one input,
	// over all its sections. Captures have a handful per section; a file
	// merged from thousands of captures stays below it.
	DefaultMaxInterfaces = 65536
	// DefaultMaxSections is the number of pcapng sections read from one
	// input. A capture has one; files joined end to end have one each
	// (hourly files of seven years are 61,000).
	DefaultMaxSections = 65536
	// DefaultMaxText is the number of bytes of interface and section option
	// text (names, descriptions, comments) kept from one input: 250 bytes
	// for each of the interfaces and sections above.
	DefaultMaxText = 16 << 20
	maxOptions     = 64 << 10 // largest options area that is parsed
)

// Packet is one packet record. Data is valid until the next call to Next.
type Packet struct {
	Frame    uint64 // 1-based over all packet records, as Wireshark numbers frames
	Part     uint16 // index of the input file (set by the caller; the reader reads one)
	Offset   int64  // start of the record or block in the uncompressed stream
	Iface    uint32 // index into Interfaces (all sections); 0 for classic pcap
	TimeNS   int64  // capture time, UTC nanoseconds since the Unix epoch
	HasTime  bool   // false for a pcapng Simple Packet Block, and for a time that does not fit in TimeNS
	CapLen   uint32
	OrigLen  uint32
	LinkType uint16
	Data     []byte
}

// Truncated reports whether the snap length cut the packet.
func (p *Packet) Truncated() bool { return p.CapLen < p.OrigLen }

// Interface describes a capture interface. Classic pcap has one.
type Interface struct {
	Section     int    // pcapng section number, 0-based
	LinkType    uint16 // LINKTYPE_ value
	SnapLen     uint32 // 0: unlimited
	TSResol     byte   // pcapng if_tsresol (6 = µs, 9 = ns; bit 7 set: power of 2)
	TSOffset    int64  // if_tsoffset, seconds
	Name        string
	Description string
	OS          string
	Packets     uint64 // packets read on this interface
	Stats       *InterfaceStats
}

// InterfaceStats is the last Interface Statistics Block of an interface.
// A nil field was not present.
type InterfaceStats struct {
	TimeNS       int64
	IfRecv       *uint64
	IfDrop       *uint64
	FilterAccept *uint64
	OSDrop       *uint64
	UsrDeliv     *uint64
}

// Section is the metadata of a pcapng Section Header Block.
type Section struct {
	BigEndian   bool
	Application string
	OS          string
	Hardware    string
	Comment     string
}

// Counters report what the reader skipped or tolerated.
type Counters struct {
	SimplePackets  uint64 // packets without a timestamp (SPB)
	SkippedBlocks  uint64 // damaged blocks with a plausible length, skipped
	UnknownBlocks  uint64 // block types that are not read (NRB, DSB, custom, ...)
	ObsoletePacket uint64 // obsolete Packet Blocks (type 2), read like EPB
	OtherFrames    uint64 // custom and systemd journal blocks: not packets, but Wireshark numbers them as frames
	BadOptions     uint64 // option areas that did not parse (ignored), and text options not kept (Options.MaxText)
	BadTimestamps  uint64 // packets whose time does not fit in 64-bit nanoseconds: read without a time
	TruncatedTail  bool   // the last record or block was cut short
}

// Options bound the reader. A field that is zero or negative takes its
// default.
type Options struct {
	MaxPacket     int   // default DefaultMaxPacket
	MaxBlock      int   // default DefaultMaxBlock
	MaxBytes      int64 // bytes read after decompression; default DefaultMaxBytes
	MaxInterfaces int   // default DefaultMaxInterfaces
	MaxSections   int   // default DefaultMaxSections
	MaxText       int   // default DefaultMaxText
}

func (o Options) withDefaults() Options {
	if o.MaxPacket <= 0 {
		o.MaxPacket = DefaultMaxPacket
	}
	if o.MaxBlock <= 0 {
		o.MaxBlock = DefaultMaxBlock
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxInterfaces <= 0 {
		o.MaxInterfaces = DefaultMaxInterfaces
	}
	if o.MaxSections <= 0 {
		o.MaxSections = DefaultMaxSections
	}
	if o.MaxText <= 0 {
		o.MaxText = DefaultMaxText
	}
	return o
}

// Reader reads one trace stream.
type Reader struct {
	src      *countingReader
	r        *bufio.Reader
	off      int64
	frame    uint64
	format   Format
	gzip     bool
	bo       binary.ByteOrder
	nanos    bool
	ifaces   []Interface
	secBase  int // index of the current section's first interface
	sections []Section
	c        Counters
	opts     Options
	maxPkt   uint32 // opts.MaxPacket as a capture length
	maxBlk   uint32 // opts.MaxBlock as a block length
	text     int    // bytes of option text kept so far
	buf      []byte
	hdr      [32]byte
	done     bool
}

type countingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

// lengthLimit converts a limit of Options to the 32-bit lengths of a
// capture. A limit above the largest 32-bit length limits nothing, so it
// becomes that length instead of wrapping around.
func lengthLimit(n int) uint32 {
	if uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// startErr is the error of an input whose format cannot be told: what says
// how far it got. The end of the input is not a cause to keep; a read error
// of the input is, so that a caller can tell a failed read from an input
// that is not a capture.
func startErr(err error, what string) error {
	if err == io.EOF {
		return fmt.Errorf("%w: %s", ErrFormat, what)
	}
	return fmt.Errorf("%w: %s: %w", ErrFormat, what, err)
}

// NewReader detects the format from the first bytes, never from a name.
func NewReader(r io.Reader, opts Options) (*Reader, error) {
	opts = opts.withDefaults()
	src := &countingReader{r: r, h: sha256.New()}
	rd := &Reader{src: src, r: bufio.NewReaderSize(src, 256<<10), opts: opts, buf: make([]byte, 64<<10),
		maxPkt: lengthLimit(opts.MaxPacket), maxBlk: lengthLimit(opts.MaxBlock)}
	head, err := rd.r.Peek(4)
	if err != nil {
		return nil, startErr(err, fmt.Sprintf("%d bytes", len(head)))
	}
	if head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(rd.r)
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %w", ErrFormat, err)
		}
		zr.Multistream(true)
		rd.r = bufio.NewReaderSize(zr, 256<<10)
		rd.gzip = true
		if head, err = rd.r.Peek(4); err != nil {
			return nil, startErr(err, fmt.Sprintf("gzip stream with %d bytes", len(head)))
		}
	}
	switch m := binary.LittleEndian.Uint32(head); m {
	case 0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1:
		rd.format = Pcap
		if err := rd.pcapHeader(); err != nil {
			return nil, err
		}
	case 0x0A0D0D0A:
		rd.format = PcapNG
	default:
		return nil, fmt.Errorf("%w: first bytes % x", ErrFormat, head)
	}
	return rd, nil
}

// Format returns the detected format.
func (rd *Reader) Format() Format { return rd.format }

// Gzip reports whether the stream was gzip-compressed.
func (rd *Reader) Gzip() bool { return rd.gzip }

// Interfaces returns the interfaces seen so far, over all sections.
func (rd *Reader) Interfaces() []Interface { return rd.ifaces }

// Sections returns the pcapng sections seen so far.
func (rd *Reader) Sections() []Section { return rd.sections }

// Counters returns what the reader skipped or tolerated so far.
func (rd *Reader) Counters() Counters { return rd.c }

// SHA256 returns the hash of the raw input (compressed bytes for gzip).
// After Next returned io.EOF it covers the whole input.
func (rd *Reader) SHA256() [32]byte {
	var s [32]byte
	copy(s[:], rd.src.h.Sum(nil))
	return s
}

// InputBytes returns the number of raw input bytes consumed so far.
func (rd *Reader) InputBytes() int64 { return rd.src.n }

// Offset returns the number of bytes of the uncompressed stream read so
// far: at most Options.MaxBytes (and the 24 bytes of a pcap file header).
func (rd *Reader) Offset() int64 { return rd.off }

// read fills b from the uncompressed stream, within Options.MaxBytes. When
// b ends past the limit, it reads up to the limit and returns ErrLimit if
// the stream goes on from there; a stream that ends at or before the limit
// ends as it does without one.
func (rd *Reader) read(b []byte) error {
	room := rd.opts.MaxBytes - rd.off
	if int64(len(b)) <= room {
		n, err := io.ReadFull(rd.r, b)
		rd.off += int64(n)
		return err
	}
	room = max(room, 0)
	n, err := io.ReadFull(rd.r, b[:room])
	rd.off += int64(n)
	if err != nil {
		return err
	}
	switch _, err := rd.r.Peek(1); {
	case err == nil:
		return ErrLimit
	case err != io.EOF:
		return err
	case n == 0:
		return io.EOF
	default:
		return io.ErrUnexpectedEOF
	}
}

// data reads n bytes into the reader's buffer. A buffer that has to grow
// grows as the bytes arrive, so a length the input does not hold is never
// allocated.
func (rd *Reader) data(n int) ([]byte, error) {
	b := rd.buf[:cap(rd.buf)]
	if n <= len(b) {
		return b[:n], rd.read(b[:n])
	}
	for have := 0; ; {
		if err := rd.read(b[have:]); err != nil {
			return nil, err
		}
		if have = len(b); have == n {
			rd.buf = b
			return b, nil
		}
		grown := make([]byte, min(n, 2*have))
		copy(grown, b)
		b = grown
	}
}

// end ends the read after err from a read of the input. The end of the
// input is io.EOF (TruncatedTail when it came inside a record or block,
// inside says whether the read started inside one); an input that goes on
// past Options.MaxBytes wraps ErrLimit; any other error, a failed read or a
// gzip stream whose checksum does not match, wraps ErrCorrupt.
func (rd *Reader) end(err error, inside bool) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return rd.eof(inside || errors.Is(err, io.ErrUnexpectedEOF))
	}
	rd.done = true
	if errors.Is(err, ErrLimit) {
		return fmt.Errorf("%w: more than %d bytes", ErrLimit, rd.opts.MaxBytes)
	}
	return fmt.Errorf("%w: reading at offset %d: %w", ErrCorrupt, rd.off, err)
}

// eof ends the read at the end of the input: it drains what is left so
// that the hash covers the whole input. A read error while draining wraps
// ErrCorrupt.
func (rd *Reader) eof(truncated bool) error {
	if truncated {
		rd.c.TruncatedTail = true
	}
	if !rd.done {
		rd.done = true
		if _, err := io.Copy(io.Discard, rd.src); err != nil {
			return fmt.Errorf("%w: reading after offset %d: %w", ErrCorrupt, rd.off, err)
		}
	}
	return io.EOF
}

// pcapHeader reads the file header of a classic pcap file. Its 24 bytes
// are read whatever Options.MaxBytes is, so that the limit ends the read at
// a record and never before the format is known.
func (rd *Reader) pcapHeader() error {
	h := rd.hdr[:24]
	n, err := io.ReadFull(rd.r, h)
	rd.off += int64(n)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF // the input ended inside the header: no cause to keep
		}
		return startErr(err, "pcap header cut short")
	}
	switch binary.LittleEndian.Uint32(h) {
	case 0xa1b2c3d4:
		rd.bo = binary.LittleEndian
	case 0xa1b23c4d:
		rd.bo, rd.nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		rd.bo = binary.BigEndian
	case 0x4d3cb2a1:
		rd.bo, rd.nanos = binary.BigEndian, true
	}
	resol := byte(6)
	if rd.nanos {
		resol = 9
	}
	// The link type is the low 16 bits; the upper bits carry the FCS length
	// and are ignored.
	rd.ifaces = []Interface{{LinkType: uint16(rd.bo.Uint32(h[20:])), SnapLen: rd.bo.Uint32(h[16:]), TSResol: resol}}
	return nil
}

// Next reads the next packet into p. It returns io.EOF at the end (also
// after a cut-short last record, see Counters), and an error wrapping
// ErrCorrupt when the file is damaged beyond what can be skipped.
func (rd *Reader) Next(p *Packet) error {
	if rd.done {
		return io.EOF
	}
	if rd.format == PcapNG {
		return rd.nextNG(p)
	}
	h := rd.hdr[:16]
	start := rd.off
	if err := rd.read(h); err != nil {
		return rd.end(err, false)
	}
	capLen, origLen := rd.bo.Uint32(h[8:]), rd.bo.Uint32(h[12:])
	if capLen > rd.maxPkt {
		rd.done = true
		return fmt.Errorf("%w: record at offset %d has a captured length of %d bytes", ErrCorrupt, start, capLen)
	}
	d, err := rd.data(int(capLen))
	if err != nil {
		return rd.end(err, true)
	}
	sub := int64(rd.bo.Uint32(h[4:]))
	if !rd.nanos {
		sub *= 1000
	}
	if sub >= 1e9 {
		rd.done = true
		return fmt.Errorf("%w: record at offset %d has a sub-second part of %d", ErrCorrupt, start, sub)
	}
	rd.frame++
	rd.ifaces[0].Packets++
	*p = Packet{Frame: rd.frame, Offset: start, TimeNS: int64(rd.bo.Uint32(h[0:]))*1e9 + sub, HasTime: true,
		CapLen: capLen, OrigLen: max(origLen, capLen), LinkType: rd.ifaces[0].LinkType, Data: d}
	return nil
}

// pcapng block types.
const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 1
	blockPB  = 2
	blockSPB = 3
	blockNRB = 4
	blockISB = 5
	blockEPB = 6
	blockSJE = 9          // systemd Journal Export
	blockCB  = 0x0BAD     // Custom Block, may be copied
	blockCBN = 0x40000BAD // Custom Block, must not be copied
)

func (rd *Reader) nextNG(p *Packet) error {
	for {
		start := rd.off
		h := rd.hdr[:12]
		if err := rd.read(h[:8]); err != nil {
			return rd.end(err, false)
		}
		if binary.LittleEndian.Uint32(h) == blockSHB {
			if err := rd.section(start, h); err != nil {
				return err
			}
			continue
		}
		if rd.bo == nil {
			rd.done = true
			return fmt.Errorf("%w: no section header before offset %d", ErrFormat, start)
		}
		typ, n := rd.bo.Uint32(h[0:]), rd.bo.Uint32(h[4:])
		if n < 12 || n%4 != 0 || n > rd.maxBlk {
			rd.done = true
			return fmt.Errorf("%w: block at offset %d has a length of %d", ErrCorrupt, start, n)
		}
		block, err := rd.data(int(n) - 8)
		if err != nil {
			return rd.end(err, true)
		}
		if rd.bo.Uint32(block[len(block)-4:]) != n {
			rd.c.SkippedBlocks++ // the trailing length disagrees: damaged
			continue
		}
		body := block[:len(block)-4]
		switch typ {
		case blockIDB:
			rd.idb(body)
		case blockEPB, blockPB:
			if ok := rd.epb(typ, start, body, p); ok {
				return nil
			}
		case blockSPB:
			if ok := rd.spb(start, body, p); ok {
				return nil
			}
		case blockISB:
			rd.isb(body)
		case blockSJE, blockCB, blockCBN:
			// Not packets, but Wireshark (4.6) numbers them as frames; count
			// them so that frame numbers stay the same as Wireshark's.
			rd.frame++
			rd.c.OtherFrames++
		default:
			rd.c.UnknownBlocks++
		}
	}
}

func (rd *Reader) section(start int64, h []byte) error {
	if err := rd.read(h[8:12]); err != nil {
		return rd.end(err, true)
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(h[8:]) {
	case 0x1A2B3C4D:
		bo = binary.LittleEndian
	case 0x4D3C2B1A:
		bo = binary.BigEndian
	default:
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d has no byte-order magic", ErrCorrupt, start)
	}
	n := bo.Uint32(h[4:])
	if n < 28 || n%4 != 0 || n > rd.maxBlk {
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d has a length of %d", ErrCorrupt, start, n)
	}
	if len(rd.sections) >= rd.opts.MaxSections {
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d: more than %d sections", ErrLimit, start, rd.opts.MaxSections)
	}
	block, err := rd.data(int(n) - 12)
	if err != nil {
		return rd.end(err, true)
	}
	rd.bo = bo
	rd.secBase = len(rd.ifaces)
	s := Section{BigEndian: bo == binary.BigEndian}
	if bo.Uint32(block[len(block)-4:]) == n {
		// version (4) and section length (8) precede the options
		rd.options(block[12:len(block)-4], func(code uint16, v []byte) {
			switch code {
			case 1:
				s.Comment = rd.keep(v)
			case 2:
				s.Hardware = rd.keep(v)
			case 3:
				s.OS = rd.keep(v)
			case 4:
				s.Application = rd.keep(v)
			}
		})
	} else {
		rd.c.SkippedBlocks++
	}
	rd.sections = append(rd.sections, s)
	return nil
}

// keep returns option text as a string to keep, within Options.MaxText over
// the whole input; text past the limit is left out and counted.
func (rd *Reader) keep(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	if len(v) > rd.opts.MaxText-rd.text {
		rd.c.BadOptions++
		return ""
	}
	rd.text += len(v)
	return string(v)
}

// idb adds the interface of an Interface Description Block. A block past
// Options.MaxInterfaces is skipped and counted like a damaged one, and so are
// the packets that name its interface, as for any interface never described.
func (rd *Reader) idb(body []byte) {
	if len(body) < 8 || len(rd.ifaces) >= rd.opts.MaxInterfaces {
		rd.c.SkippedBlocks++
		return
	}
	f := Interface{Section: len(rd.sections) - 1, LinkType: rd.bo.Uint16(body), SnapLen: rd.bo.Uint32(body[4:]), TSResol: 6}
	rd.options(body[8:], func(code uint16, v []byte) {
		switch {
		case code == 2:
			f.Name = rd.keep(v)
		case code == 3:
			f.Description = rd.keep(v)
		case code == 9 && len(v) >= 1:
			if _, ok := unitsPerSecond(v[0]); ok {
				f.TSResol = v[0]
			} else {
				rd.c.BadOptions++
			}
		case code == 12:
			f.OS = rd.keep(v)
		case code == 14 && len(v) >= 8:
			f.TSOffset = int64(rd.bo.Uint64(v))
		}
	})
	rd.ifaces = append(rd.ifaces, f)
}

func (rd *Reader) epb(typ uint32, start int64, body []byte, p *Packet) bool {
	if len(body) < 20 {
		rd.c.SkippedBlocks++
		return false
	}
	var id uint32
	if typ == blockPB {
		id = uint32(rd.bo.Uint16(body)) // obsolete Packet Block: 16-bit interface, 16-bit drops count
		rd.c.ObsoletePacket++
	} else {
		id = rd.bo.Uint32(body)
	}
	capLen := rd.bo.Uint32(body[12:])
	g := rd.secBase + int(id) // id < len: int(id) stays positive on 32-bit platforms
	if id >= uint32(len(rd.ifaces)) || g >= len(rd.ifaces) || capLen > rd.maxPkt || int(capLen) > len(body)-20 {
		rd.c.SkippedBlocks++
		return false
	}
	f := &rd.ifaces[g]
	ts := uint64(rd.bo.Uint32(body[4:]))<<32 | uint64(rd.bo.Uint32(body[8:]))
	// A time that does not fit in 64-bit nanoseconds leaves the packet
	// without one, and is counted.
	ns, ok := toNS(ts, f.TSResol, f.TSOffset)
	if !ok {
		rd.c.BadTimestamps++
	}
	rd.frame++
	f.Packets++
	*p = Packet{Frame: rd.frame, Offset: start, Iface: uint32(g), TimeNS: ns, HasTime: ok,
		CapLen: capLen, OrigLen: max(rd.bo.Uint32(body[16:]), capLen), LinkType: f.LinkType, Data: body[20 : 20+capLen]}
	return true
}

func (rd *Reader) spb(start int64, body []byte, p *Packet) bool {
	g := rd.secBase
	if g >= len(rd.ifaces) || len(body) < 4 {
		rd.c.SkippedBlocks++
		return false
	}
	f := &rd.ifaces[g]
	orig := rd.bo.Uint32(body)
	capLen := min(uint32(len(body)-4), orig)
	if f.SnapLen != 0 {
		capLen = min(capLen, f.SnapLen)
	}
	if capLen > rd.maxPkt {
		rd.c.SkippedBlocks++
		return false
	}
	rd.frame++
	f.Packets++
	rd.c.SimplePackets++
	*p = Packet{Frame: rd.frame, Offset: start, Iface: uint32(g), CapLen: capLen, OrigLen: max(orig, capLen),
		LinkType: f.LinkType, Data: body[4 : 4+capLen]}
	return true
}

func (rd *Reader) isb(body []byte) {
	if len(body) < 12 {
		rd.c.SkippedBlocks++
		return
	}
	id := rd.bo.Uint32(body)
	g := rd.secBase + int(id)
	if id >= uint32(len(rd.ifaces)) || g >= len(rd.ifaces) {
		rd.c.SkippedBlocks++
		return
	}
	f := &rd.ifaces[g]
	ts := uint64(rd.bo.Uint32(body[4:]))<<32 | uint64(rd.bo.Uint32(body[8:]))
	ns, _ := toNS(ts, f.TSResol, f.TSOffset) // 0 when it does not fit
	s := &InterfaceStats{TimeNS: ns}
	rd.options(body[12:], func(code uint16, v []byte) {
		if len(v) < 8 {
			return
		}
		x := rd.bo.Uint64(v)
		switch code {
		case 4:
			s.IfRecv = &x
		case 5:
			s.IfDrop = &x
		case 6:
			s.FilterAccept = &x
		case 7:
			s.OSDrop = &x
		case 8:
			s.UsrDeliv = &x
		}
	})
	f.Stats = s
}

// options walks a pcapng options area; a malformed area is counted and the
// rest of it ignored.
func (rd *Reader) options(b []byte, fn func(code uint16, v []byte)) {
	if len(b) > maxOptions {
		rd.c.BadOptions++
		return
	}
	for len(b) >= 4 {
		code, n := rd.bo.Uint16(b), int(rd.bo.Uint16(b[2:]))
		if code == 0 {
			return
		}
		if 4+n > len(b) {
			rd.c.BadOptions++
			return
		}
		fn(code, b[4:4+n])
		b = b[min(len(b), 4+(n+3)&^3):]
	}
}

// unitsPerSecond decodes if_tsresol.
func unitsPerSecond(r byte) (uint64, bool) {
	if r&0x80 != 0 {
		e := r & 0x7F
		if e > 63 {
			return 0, false
		}
		return 1 << e, true
	}
	if r > 19 {
		return 0, false
	}
	u := uint64(1)
	for range r {
		u *= 10
	}
	return u, true
}

// toNS converts a pcapng timestamp in if_tsresol units, with the interface's
// if_tsoffset in seconds, to UTC nanoseconds. The sub-second part is exact
// (128-bit intermediate). It reports false when the time does not fit in 64
// bits of nanoseconds (it lies before 1677-09-21 or after 2262-04-11):
// nothing wraps around.
func toNS(ts uint64, resol byte, offset int64) (int64, bool) {
	const second = 1_000_000_000
	u, ok := unitsPerSecond(resol)
	if !ok {
		u = 1e6
	}
	sec, frac := ts/u, ts%u
	hi, lo := bits.Mul64(frac, second)
	ns, _ := bits.Div64(hi, lo, u) // below one second
	// sec + offset, a 64-bit unsigned count plus a signed one, without
	// leaving the range of either: the sum is whole seconds after 1970, or
	// back seconds before it.
	var whole, back uint64
	if offset >= 0 {
		whole = sec + uint64(offset)
		if whole < sec {
			return 0, false
		}
	} else if neg := uint64(-(offset + 1)) + 1; sec >= neg { // neg is -offset, also for the smallest int64
		whole = sec - neg
	} else {
		back = neg - sec
	}
	if back == 0 {
		if whole > math.MaxInt64/second {
			return 0, false
		}
		v := whole*second + ns
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	}
	if back > math.MaxInt64/second+1 {
		return 0, false
	}
	v := back*second - ns // nanoseconds before 1970: at most 2^63
	if v > 1<<63 {
		return 0, false
	}
	return -int64(v), true // also for 2^63, the smallest int64
}
