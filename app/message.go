package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

// headerSize is the length in bytes of the header section, which is the same
// for every DNS message.
const headerSize = 12

// maxUDPSize is the size in bytes of the largest DNS message that may be sent
// over UDP (RFC 1035, section 4.2.1).
const maxUDPSize = 512

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

// Operation codes, the kind of query a message carries (RFC 1035, section 4.1.1).
const (
	OpcodeQuery uint8 = 0 // A standard query.
)

// Response codes (RFC 1035, section 4.1.1).
const (
	RCodeNoError        uint8 = 0 // No error condition.
	RCodeFormatError    uint8 = 1 // The server was unable to interpret the query.
	RCodeNotImplemented uint8 = 4 // The server does not support this kind of query.
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

// parseHeader decodes the header section found in the first 12 bytes of a DNS
// message. Anything after the header is left alone.
func parseHeader(data []byte) (Header, error) {
	if len(data) < headerSize {
		return Header{}, fmt.Errorf("message is %d bytes long, too short for its %d-byte header",
			len(data), headerSize)
	}

	flags := binary.BigEndian.Uint16(data[2:])

	return Header{
		ID:      binary.BigEndian.Uint16(data[0:]),
		QR:      flags&flagQR != 0,
		Opcode:  uint8(flags >> opcodeShift & opcodeMask),
		AA:      flags&flagAA != 0,
		TC:      flags&flagTC != 0,
		RD:      flags&flagRD != 0,
		RA:      flags&flagRA != 0,
		Z:       uint8(flags >> zShift & zMask),
		RCode:   uint8(flags & rcodeMask),
		QDCount: binary.BigEndian.Uint16(data[4:]),
		ANCount: binary.BigEndian.Uint16(data[6:]),
		NSCount: binary.BigEndian.Uint16(data[8:]),
		ARCount: binary.BigEndian.Uint16(data[10:]),
	}, nil
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

// parseQuestion decodes the question that starts at offset in the DNS message
// data. It returns the question and the offset of the byte that follows it.
func parseQuestion(data []byte, offset int) (Question, int, error) {
	name, offset, err := parseName(data, offset)
	if err != nil {
		return Question{}, 0, err
	}

	// The name is followed by the type and the class, two bytes each.
	if len(data)-offset < 4 {
		return Question{}, 0, errors.New("message ends before the type and class of the question")
	}

	question := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset:]),
		Class: binary.BigEndian.Uint16(data[offset+2:]),
	}

	return question, offset + 4, nil
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

// parseName decodes the domain name that starts at offset in the DNS message
// data. It returns the name and the offset of the byte that follows it.
//
// The labels of the name are joined with dots, without a trailing dot:
// \x06google\x03com\x00 becomes "google.com". The root, which has no labels, is
// returned as ".".
func parseName(data []byte, offset int) (string, int, error) {
	var name []byte

	for {
		if offset >= len(data) {
			return "", 0, errors.New("message ends in the middle of a domain name")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		// A length byte with either of its top two bits set is not a plain
		// length. Compressed names, which use both bits, are not supported.
		if length > maxLabelLength {
			return "", 0, fmt.Errorf("domain name has an unsupported label type %#02x", length)
		}
		if length > len(data)-offset {
			return "", 0, errors.New("message ends in the middle of a domain name label")
		}

		label := data[offset : offset+length]
		offset += length

		// A dot inside a label could not be told apart from the dots that
		// separate labels once the name is written as text.
		if bytes.IndexByte(label, '.') >= 0 {
			return "", 0, fmt.Errorf("domain name has a label that contains a dot: %q", label)
		}

		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, label...)

		// The text form is two bytes shorter than the wire format, which has
		// a length byte per label instead of the dots and a terminating zero.
		if len(name)+2 > maxNameLength {
			return "", 0, fmt.Errorf("domain name takes more than %d bytes to encode", maxNameLength)
		}
	}

	if len(name) == 0 {
		return ".", offset, nil
	}

	return string(name), offset, nil
}

// Message is a DNS message. Of its five sections (header, question, answer,
// authority and additional) the authority and additional sections are not
// supported yet.
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// Encode returns the wire format of the message, however long that is.
//
// QDCOUNT and ANCOUNT are taken from the number of questions and answers in
// the message rather than from Header.QDCount and Header.ANCount, so the header
// cannot disagree with the sections that follow it.
func (m Message) Encode() ([]byte, error) {
	return m.EncodeWithLimit(math.MaxInt)
}

// EncodeWithLimit returns the wire format of as much of the message as fits
// in limit bytes, for transports that restrict the size of a message.
//
// Questions and then answers are encoded in order until one does not fit.
// That entry and all those after it are left out, and the TC flag is set to
// tell the receiver that the message is incomplete. QDCOUNT and ANCOUNT count
// the entries that were encoded.
func (m Message) EncodeWithLimit(limit int) ([]byte, error) {
	if limit < headerSize {
		return nil, fmt.Errorf("limit of %d bytes leaves no room for the %d-byte header", limit, headerSize)
	}
	if len(m.Questions) > math.MaxUint16 {
		return nil, fmt.Errorf("message has %d questions, the limit is %d", len(m.Questions), math.MaxUint16)
	}
	if len(m.Answers) > math.MaxUint16 {
		return nil, fmt.Errorf("message has %d answers, the limit is %d", len(m.Answers), math.MaxUint16)
	}

	// The header comes first on the wire but is written last, once it is
	// known how many entries fit.
	buf := make([]byte, headerSize, maxUDPSize)

	questions, answers := 0, 0
	complete := true

	for _, question := range m.Questions {
		extended, err := question.appendTo(buf)
		if err != nil {
			return nil, err
		}
		if len(extended) > limit {
			complete = false
			break
		}

		buf = extended
		questions++
	}

	for i := 0; complete && i < len(m.Answers); i++ {
		extended, err := m.Answers[i].appendTo(buf)
		if err != nil {
			return nil, err
		}
		if len(extended) > limit {
			complete = false
			break
		}

		buf = extended
		answers++
	}

	header := m.Header
	header.QDCount = uint16(questions)
	header.ANCount = uint16(answers)
	header.TC = header.TC || !complete

	copy(buf, header.appendTo(nil))

	return buf, nil
}

// parseMessage decodes a DNS message: its header and its question section.
// The records of the other sections are not decoded.
func parseMessage(data []byte) (Message, error) {
	header, err := parseHeader(data)
	if err != nil {
		return Message{}, err
	}

	message := Message{Header: header}
	offset := headerSize

	for i := 0; i < int(header.QDCount); i++ {
		var question Question

		question, offset, err = parseQuestion(data, offset)
		if err != nil {
			return Message{}, fmt.Errorf("question %d of %d: %w", i+1, header.QDCount, err)
		}

		message.Questions = append(message.Questions, question)
	}

	return message, nil
}
