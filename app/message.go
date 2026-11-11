package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
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
	// byte has only six usable bits: the top two say what kind of label it is.
	maxLabelLength = 63

	// maxNameLength is the longest a name may be once encoded without
	// compression, counting every length byte and the terminating zero byte.
	maxNameLength = 255
)

// Message compression (RFC 1035, section 4.1.4). A name, or the tail end of
// one, can be replaced with a two-byte pointer to an earlier occurrence of the
// same labels. A pointer has the top two bits of its first byte set, which
// tells it apart from a label, and holds an offset from the start of the
// message in its other 14 bits.
const (
	labelTypeMask    = 0xC0
	labelTypePointer = 0xC0
	pointerMask      = 0x3FFF
)

// Operation codes, the kind of query a message carries (RFC 1035, section 4.1.1).
const (
	OpcodeQuery uint8 = 0 // A standard query.
)

// Response codes (RFC 1035, section 4.1.1).
const (
	RCodeNoError        uint8 = 0 // No error condition.
	RCodeFormatError    uint8 = 1 // The server was unable to interpret the query.
	RCodeServerFailure  uint8 = 2 // The server was unable to process the query.
	RCodeNotImplemented uint8 = 4 // The server does not support this kind of query.
)

// Record types (RFC 1035, section 3.2.2).
const (
	TypeA     uint16 = 1  // An IPv4 host address.
	TypeNS    uint16 = 2  // An authoritative name server.
	TypeCNAME uint16 = 5  // The canonical name for an alias.
	TypeSOA   uint16 = 6  // The start of a zone of authority.
	TypePTR   uint16 = 12 // A domain name pointer.
	TypeMX    uint16 = 15 // A mail exchange.
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

	// Data is the record data (RDATA): for an A record, the 4 bytes of an IPv4
	// address. Domain names in it are never compressed, because a pointer
	// only means something inside the message it was read from.
	Data []byte
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

// parseResourceRecord decodes the record that starts at offset in the DNS
// message data. It returns the record and the offset of the byte that follows
// it.
func parseResourceRecord(data []byte, offset int) (ResourceRecord, int, error) {
	name, offset, err := parseName(data, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}

	// The name is followed by the type (2 bytes), the class (2), the TTL (4)
	// and the length of the data (2).
	if len(data)-offset < 10 {
		return ResourceRecord{}, 0, errors.New("message ends before the type, class, TTL and data length of the record")
	}

	record := ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset:]),
		Class: binary.BigEndian.Uint16(data[offset+2:]),
		TTL:   binary.BigEndian.Uint32(data[offset+4:]),
	}
	length := int(binary.BigEndian.Uint16(data[offset+8:]))
	offset += 10

	if length > len(data)-offset {
		return ResourceRecord{}, 0, errors.New("message ends in the middle of the data of the record")
	}

	record.Data, err = parseRecordData(data, offset, length, record.Type)
	if err != nil {
		return ResourceRecord{}, 0, err
	}

	return record, offset + length, nil
}

// domainName marks a domain name in the layouts of recordDataLayouts.
const domainName = 0

// recordDataLayouts describes the data of the record types that may have
// compressed domain names in it. Those are the types defined in RFC 1035, and
// no others (RFC 3597, section 4). The parts of the data are listed in order:
// domainName stands for a domain name, any other value for that many bytes.
var recordDataLayouts = map[uint16][]int{
	TypeNS:    {domainName},
	3:         {domainName}, // MD, a mail destination (obsolete).
	4:         {domainName}, // MF, a mail forwarder (obsolete).
	TypeCNAME: {domainName},
	TypeSOA:   {domainName, domainName, 20}, // Primary server, mailbox, then five 32-bit numbers.
	7:         {domainName},                 // MB, a mailbox domain name (experimental).
	8:         {domainName},                 // MG, a mail group member (experimental).
	9:         {domainName},                 // MR, a mail rename domain name (experimental).
	TypePTR:   {domainName},
	14:        {domainName, domainName}, // MINFO, mailbox information (experimental).
	TypeMX:    {2, domainName},          // Preference, then the mail exchange.
}

// parseRecordData returns the data of a record of the given type, which takes
// up length bytes at offset in the DNS message data.
//
// The data is returned as it is, except for the record types that may have
// compressed domain names in it. Those names are written out in full, so that
// the data still makes sense once it is taken out of this message.
func parseRecordData(data []byte, offset, length int, recordType uint16) ([]byte, error) {
	end := offset + length

	layout, mayBeCompressed := recordDataLayouts[recordType]
	if !mayBeCompressed {
		return append([]byte(nil), data[offset:end]...), nil
	}

	var expanded []byte

	for _, part := range layout {
		if part != domainName {
			if part > end-offset {
				return nil, fmt.Errorf("data of record of type %d is cut short", recordType)
			}

			expanded = append(expanded, data[offset:offset+part]...)
			offset += part

			continue
		}

		name, next, err := parseName(data, offset)
		if err != nil {
			return nil, err
		}

		// What a pointer leads to may be anywhere earlier in the message,
		// but the name itself has to stay within the data of its record.
		if next > end {
			return nil, fmt.Errorf("domain name in data of record of type %d runs past the end of the data", recordType)
		}

		if expanded, err = appendName(expanded, name); err != nil {
			return nil, err
		}
		offset = next
	}

	if offset != end {
		return nil, fmt.Errorf("data of record of type %d is %d bytes too long", recordType, end-offset)
	}

	return expanded, nil
}

// appendName appends the wire format of a domain name to buf and returns the
// extended buffer. A name is encoded as a sequence of labels, each one prefixed
// with a byte holding its length, and ends with a zero byte:
// "google.com" becomes \x06google\x03com\x00.
//
// A single trailing dot is accepted and ignored, so "google.com." encodes the
// same way. Both "" and "." stand for the root, which is the zero byte alone.
//
// A backslash takes away the special meaning of the character after it, which
// is how a label can hold a dot: `first\.last.example.com` has three labels.
// A backslash followed by three decimal digits stands for the byte with that
// value (RFC 1035, section 5.1).
func appendName(buf []byte, name string) ([]byte, error) {
	start := len(buf)

	text := name
	if text == "." {
		text = ""
	}

	// The length of a label is written in front of it, but is only known once
	// its end is reached. A byte is set aside for it in the meantime.
	lengthAt := len(buf)
	buf = append(buf, 0)

	for i := 0; i < len(text); i++ {
		c := text[i]

		switch c {
		case '.':
			length := len(buf) - lengthAt - 1
			if length == 0 {
				return nil, fmt.Errorf("domain name %q has an empty label", name)
			}
			if length > maxLabelLength {
				return nil, fmt.Errorf("domain name %q has a label of %d bytes, the limit is %d",
					name, length, maxLabelLength)
			}

			buf[lengthAt] = byte(length)
			lengthAt = len(buf)
			buf = append(buf, 0)

			continue

		case '\\':
			escaped, size, err := unescape(text[i+1:])
			if err != nil {
				return nil, fmt.Errorf("domain name %q %w", name, err)
			}

			c = escaped
			i += size
		}

		buf = append(buf, c)
	}

	// After a trailing dot, and in the root, there is no label left to end:
	// the byte set aside for the next length is the zero that ends the name.
	if length := len(buf) - lengthAt - 1; length > 0 {
		if length > maxLabelLength {
			return nil, fmt.Errorf("domain name %q has a label of %d bytes, the limit is %d",
				name, length, maxLabelLength)
		}

		buf[lengthAt] = byte(length)
		buf = append(buf, 0)
	}

	if encoded := len(buf) - start; encoded > maxNameLength {
		return nil, fmt.Errorf("domain name %q takes %d bytes to encode, the limit is %d",
			name, encoded, maxNameLength)
	}

	return buf, nil
}

// unescape decodes the escape sequence at the start of text, which is what
// follows a backslash in a domain name. It returns the byte that the sequence
// stands for and the number of bytes of text that the sequence takes up.
func unescape(text string) (byte, int, error) {
	if text == "" {
		return 0, 0, errors.New("ends with a backslash that escapes nothing")
	}

	// Anything but a digit stands for itself.
	if !isDigit(text[0]) {
		return text[0], 1, nil
	}

	if len(text) < 3 || !isDigit(text[1]) || !isDigit(text[2]) {
		return 0, 0, errors.New("has a decimal escape that is not three digits long")
	}

	value := int(text[0]-'0')*100 + int(text[1]-'0')*10 + int(text[2]-'0')
	if value > math.MaxUint8 {
		return 0, 0, fmt.Errorf("has a decimal escape for %d, which is not a byte", value)
	}

	return byte(value), 3, nil
}

// isDigit reports whether c is a decimal digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// parseName decodes the domain name that starts at offset in the DNS message
// data, following compression pointers to the rest of the name where there are
// any. It returns the name and the offset of the byte that follows it.
//
// The labels of the name are joined with dots, without a trailing dot:
// \x06google\x03com\x00 becomes "google.com". The root, which has no labels, is
// returned as ".". A dot or a backslash inside a label is preceded by a
// backslash, which keeps it apart from the dots that separate labels and makes
// the name one that appendName encodes back to the same labels.
func parseName(data []byte, offset int) (string, int, error) {
	var name []byte

	// encoded is what the name takes to encode without compression. The zero
	// byte that ends it is counted from the start.
	encoded := 1

	// start is where the run of labels being read begins.
	start := offset

	// next is the offset of the byte that follows the name. A name ends at its
	// first pointer: what the pointer leads to belongs to an earlier name.
	next := -1

	for {
		if offset >= len(data) {
			return "", 0, errors.New("message ends in the middle of a domain name")
		}

		length := int(data[offset])

		if length&labelTypeMask == labelTypePointer {
			if offset+1 >= len(data) {
				return "", 0, errors.New("message ends in the middle of a compression pointer")
			}

			target := int(binary.BigEndian.Uint16(data[offset:]) & pointerMask)

			// A pointer refers to an earlier occurrence of a name, so it has
			// to lead backwards. Holding every pointer to that also keeps a
			// malicious message from sending the parser around in circles:
			// each jump lands before the run of labels that led to it, so a
			// name can only jump so many times before it runs out of message.
			if target >= start {
				return "", 0, fmt.Errorf("compression pointer at offset %d leads to offset %d, "+
					"which is not before the labels it follows", offset, target)
			}

			if next < 0 {
				next = offset + 2
			}

			offset, start = target, target
			continue
		}

		offset++

		if length == 0 {
			break
		}

		// Only one of the top two bits is set, which no label type uses.
		if length > maxLabelLength {
			return "", 0, fmt.Errorf("domain name has an unsupported label type %#02x", length)
		}
		if length > len(data)-offset {
			return "", 0, errors.New("message ends in the middle of a domain name label")
		}

		label := data[offset : offset+length]
		offset += length

		encoded += 1 + length
		if encoded > maxNameLength {
			return "", 0, fmt.Errorf("domain name takes more than %d bytes to encode", maxNameLength)
		}

		if len(name) > 0 {
			name = append(name, '.')
		}
		for _, c := range label {
			if c == '.' || c == '\\' {
				name = append(name, '\\')
			}
			name = append(name, c)
		}
	}

	if next < 0 {
		next = offset
	}

	if len(name) == 0 {
		return ".", next, nil
	}

	return string(name), next, nil
}

// Message is a DNS message. Of its five sections (header, question, answer,
// authority and additional) the authority and additional sections are not
// supported: they are skipped when a message is decoded and left empty when
// one is encoded.
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// Encode returns the wire format of the message, however long that is. Domain
// names are written out in full, without compression.
//
// The four counts in the encoded header describe what is actually encoded, not
// what the counts in Header say, so the header cannot disagree with the
// sections that follow it: QDCOUNT and ANCOUNT are the number of questions and
// answers in the message, and NSCOUNT and ARCOUNT are zero.
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
	header.NSCount = 0
	header.ARCount = 0
	header.TC = header.TC || !complete

	copy(buf, header.appendTo(nil))

	return buf, nil
}

// parseMessage decodes a DNS message: its header, its question section and its
// answer section. Domain names may be compressed. The records of the authority
// and additional sections are not decoded.
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

	for i := 0; i < int(header.ANCount); i++ {
		var answer ResourceRecord

		answer, offset, err = parseResourceRecord(data, offset)
		if err != nil {
			return Message{}, fmt.Errorf("answer %d of %d: %w", i+1, header.ANCount, err)
		}

		message.Answers = append(message.Answers, answer)
	}

	return message, nil
}
