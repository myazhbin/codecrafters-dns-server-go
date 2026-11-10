package main

import "encoding/binary"

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

// Encode returns the 12-byte wire format of the header. Integers are encoded
// in big-endian order.
func (h Header) Encode() []byte {
	buf := make([]byte, headerSize)

	binary.BigEndian.PutUint16(buf[0:], h.ID)
	binary.BigEndian.PutUint16(buf[2:], h.flags())
	binary.BigEndian.PutUint16(buf[4:], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:], h.ARCount)

	return buf
}

// Message is a DNS message. Of its five sections (header, question, answer,
// authority and additional) only the header is supported so far.
type Message struct {
	Header Header
}

// Encode returns the wire format of the message.
func (m Message) Encode() []byte {
	return m.Header.Encode()
}
