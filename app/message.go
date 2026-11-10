package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// headerSize is the length in bytes of the header section, which is the same
// for every DNS message.
const headerSize = 12

// Positions of the fields packed into the 16-bit flags word that follows the
// ID in the header:
//
//	  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	|QR |    OPCODE     |AA |TC |RD |RA |     Z     |     RCODE     |
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
const (
	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7

	opcodeShift = 11
	opcodeMask  = 0x0F
	zShift      = 4
	zMask       = 0x07
	rcodeMask   = 0x0F
)

// Limits on the wire format of a domain name (RFC 1035, section 2.3.4).
const (
	// maxLabelLength is the longest a single label may be. A label's length
	// byte has only six usable bits: the top two are reserved.
	maxLabelLength = 63

	// maxNameLength is the longest an encoded name may be, counting every
	// length byte and the terminating zero byte.
	maxNameLength = 255
)

// Record types (RFC 1035, section 3.2.2).
const (
	TypeA uint16 = 1 // An IPv4 host address.
)

// Record classes (RFC 1035, section 3.2.4).
const (
	ClassIN uint16 = 1 // The Internet.
)

// Header is the header section of a DNS message (RFC 1035, section 4.1.1).
type Header struct {
	ID      uint16 // Packet identifier. A response carries the ID of its query.
	QR      bool   // Query/response indicator: false for a query, true for a response.
	Opcode  uint8  // Kind of query. Only the low 4 bits are used.
	AA      bool   // Authoritative answer: the responding server owns the queried domain.
	TC      bool   // Truncation: the message was cut short to fit the transport.
	RD      bool   // Recursion desired: the client wants the query resolved recursively.
	RA      bool   // Recursion available: the server can resolve queries recursively.
	Z       uint8  // Reserved. Only the low 3 bits are used.
	RCode   uint8  // Response code. Only the low 4 bits are used.
	QDCount uint16 // Number of entries in the question section.
	ANCount uint16 // Number of records in the answer section.
	NSCount uint16 // Number of records in the authority section.
	ARCount uint16 // Number of records in the additional section.
}

// flags packs QR, OPCODE, AA, TC, RD, RA, Z and RCODE into the 16-bit word
// that follows the ID on the wire. Bits that do not fit a field are dropped
// rather than spilling into its neighbour.
func (h Header) flags() uint16 {
	flags := uint16(h.Opcode&opcodeMask)<<opcodeShift |
		uint16(h.Z&zMask)<<zShift |
		uint16(h.RCode&rcodeMask)

	if h.QR {
		flags |= flagQR
	}
	if h.AA {
		flags |= flagAA
	}
	if h.TC {
		flags |= flagTC
	}
	if h.RD {
		flags |= flagRD
	}
	if h.RA {
		flags |= flagRA
	}

	return flags
}

// appendTo appends the 12-byte wire format of the header to buf and returns
// the extended buffer. Integers are encoded in big-endian order.
func (h Header) appendTo(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, h.ID)
	buf = binary.BigEndian.AppendUint16(buf, h.flags())
	buf = binary.BigEndian.AppendUint16(buf, h.QDCount)
	buf = binary.BigEndian.AppendUint16(buf, h.ANCount)
	buf = binary.BigEndian.AppendUint16(buf, h.NSCount)
	buf = binary.BigEndian.AppendUint16(buf, h.ARCount)

	return buf
}

// Question is an entry in the question section of a DNS message (RFC 1035,
// section 4.1.2).
type Question struct {
	Name  string // Domain name being asked about, such as "codecrafters.io".
	Type  uint16 // Type of record being asked for, such as TypeA.
	Class uint16 // Class of record being asked for, usually ClassIN.
}

// appendTo appends the wire format of the question to buf and returns the
// extended buffer.
func (q Question) appendTo(buf []byte) ([]byte, error) {
	buf, err := appendName(buf, q.Name)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, q.Type)
	buf = binary.BigEndian.AppendUint16(buf, q.Class)

	return buf, nil
}

// ResourceRecord is an entry in the answer section of a DNS message (RFC 1035,
// section 4.1.3).
type ResourceRecord struct {
	Name  string // Domain name the record belongs to, such as "codecrafters.io".
	Type  uint16 // Type of the record, such as TypeA. It decides how Data is read.
	Class uint16 // Class of the record, usually ClassIN.
	TTL   uint32 // Number of seconds the record may be cached before asking again.
	Data  []byte // Record data (RDATA). For an A record, the 4 bytes of an IPv4 address.
}

// appendTo appends the wire format of the record to buf and returns the
// extended buffer. The length of the data (RDLENGTH) is written just before
// the data itself.
func (r ResourceRecord) appendTo(buf []byte) ([]byte, error) {
	if len(r.Data) > math.MaxUint16 {
		return nil, fmt.Errorf("record for %q has %d bytes of data, the limit is %d",
			r.Name, len(r.Data), math.MaxUint16)
	}

	buf, err := appendName(buf, r.Name)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, r.Type)
	buf = binary.BigEndian.AppendUint16(buf, r.Class)
	buf = binary.BigEndian.AppendUint32(buf, r.TTL)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	buf = append(buf, r.Data...)

	return buf, nil
}

// appendName appends the wire format of a domain name to buf and returns the
// extended buffer. A name is encoded as a sequence of labels, each one prefixed
// with a byte holding its length, and ends with a zero byte:
// "google.com" becomes \x06google\x03com\x00.
//
// A single trailing dot is accepted and ignored, so "google.com." encodes the
// same way. Both "" and "." stand for the root, which is the zero byte alone.
func appendName(buf []byte, name string) ([]byte, error) {
	start := len(buf)

	if labels := strings.TrimSuffix(name, "."); labels != "" {
		for _, label := range strings.Split(labels, ".") {
			if label == "" {
				return nil, fmt.Errorf("domain name %q has an empty label", name)
			}
			if len(label) > maxLabelLength {
				return nil, fmt.Errorf("domain name %q has a label of %d bytes, the limit is %d",
					name, len(label), maxLabelLength)
			}

			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}

	buf = append(buf, 0)

	if encoded := len(buf) - start; encoded > maxNameLength {
		return nil, fmt.Errorf("domain name %q takes %d bytes to encode, the limit is %d",
			name, encoded, maxNameLength)
	}

	return buf, nil
}

// Message is a DNS message. Of its five sections (header, question, answer,
// authority and additional) the authority and additional sections are not
// supported yet.
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// Encode returns the wire format of the message.
//
// QDCOUNT and ANCOUNT are taken from the number of questions and answers in
// the message rather than from Header.QDCount and Header.ANCount, so the header
// cannot disagree with the sections that follow it.
func (m Message) Encode() ([]byte, error) {
	if len(m.Questions) > math.MaxUint16 {
		return nil, fmt.Errorf("message has %d questions, the limit is %d", len(m.Questions), math.MaxUint16)
	}
	if len(m.Answers) > math.MaxUint16 {
		return nil, fmt.Errorf("message has %d answers, the limit is %d", len(m.Answers), math.MaxUint16)
	}

	header := m.Header
	header.QDCount = uint16(len(m.Questions))
	header.ANCount = uint16(len(m.Answers))

	buf := header.appendTo(make([]byte, 0, 512))

	var err error

	for _, question := range m.Questions {
		if buf, err = question.appendTo(buf); err != nil {
			return nil, err
		}
	}

	for _, answer := range m.Answers {
		if buf, err = answer.appendTo(buf); err != nil {
			return nil, err
		}
	}

	return buf, nil
}
