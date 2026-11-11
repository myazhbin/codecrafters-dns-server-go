package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestHeaderAppendTo(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{
			name:   "zero value is twelve zero bytes",
			header: Header{},
			want:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "reply header with ID 1234",
			header: Header{ID: 1234, QR: true},
			want:   []byte{0x04, 0xD2, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "ID is big-endian",
			header: Header{ID: 0xABCD},
			want:   []byte{0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "QR is the top bit of the flags",
			header: Header{QR: true},
			want:   []byte{0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "opcode fills bits 11 to 14",
			header: Header{Opcode: 0x0F},
			want:   []byte{0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "opcode 1 sets only bit 11",
			header: Header{Opcode: 1},
			want:   []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "AA is bit 10",
			header: Header{AA: true},
			want:   []byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "TC is bit 9",
			header: Header{TC: true},
			want:   []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "RD is bit 8",
			header: Header{RD: true},
			want:   []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "RA is bit 7",
			header: Header{RA: true},
			want:   []byte{0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "Z fills bits 4 to 6",
			header: Header{Z: 0x07},
			want:   []byte{0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "RCODE fills bits 0 to 3",
			header: Header{RCode: 0x0F},
			want:   []byte{0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "RCODE 4 sets only bit 2",
			header: Header{RCode: 4},
			want:   []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "oversized opcode does not spill into QR or AA",
			header: Header{Opcode: 0xFF},
			want:   []byte{0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "oversized Z does not spill into RA",
			header: Header{Z: 0xFF},
			want:   []byte{0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "oversized RCODE does not spill into Z",
			header: Header{RCode: 0xFF},
			want:   []byte{0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:   "counts are big-endian and in QD, AN, NS, AR order",
			header: Header{QDCount: 0x0102, ANCount: 0x0304, NSCount: 0x0506, ARCount: 0x0708},
			want:   []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name: "every field at its maximum",
			header: Header{
				ID: 0xFFFF, QR: true, Opcode: 0x0F, AA: true, TC: true, RD: true, RA: true, Z: 0x07, RCode: 0x0F,
				QDCount: 0xFFFF, ANCount: 0xFFFF, NSCount: 0xFFFF, ARCount: 0xFFFF,
			},
			want: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "a mix of fields",
			header: Header{
				ID: 0xBEEF, QR: true, Opcode: 2, RD: true, RCode: 4,
				QDCount: 1, ANCount: 2, NSCount: 3, ARCount: 4,
			},
			want: []byte{0xBE, 0xEF, 0x91, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.header.appendTo(nil)

			if len(got) != headerSize {
				t.Errorf("header is %d bytes long, want %d", len(got), headerSize)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("appendTo(nil) = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestHeaderAppendToKeepsExistingBytes(t *testing.T) {
	prefix := []byte{0xAA, 0xBB}

	got := Header{ID: 1234, QR: true}.appendTo(prefix)

	want := []byte{0xAA, 0xBB, 0x04, 0xD2, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	if !bytes.Equal(got, want) {
		t.Errorf("appendTo(prefix) = % x, want % x", got, want)
	}
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Header
	}{
		{
			name: "all zero",
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{},
		},
		{
			name: "query sent by dig",
			data: []byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{ID: 1234, RD: true, QDCount: 1},
		},
		{
			name: "ID is big-endian",
			data: []byte{0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{ID: 0xABCD},
		},
		{
			name: "QR",
			data: []byte{0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{QR: true},
		},
		{
			name: "largest OPCODE",
			data: []byte{0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Opcode: 15},
		},
		{
			name: "OPCODE 1",
			data: []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Opcode: 1},
		},
		{
			name: "AA",
			data: []byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{AA: true},
		},
		{
			name: "TC",
			data: []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{TC: true},
		},
		{
			name: "RD",
			data: []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{RD: true},
		},
		{
			name: "RA",
			data: []byte{0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{RA: true},
		},
		{
			name: "largest Z",
			data: []byte{0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Z: 7},
		},
		{
			name: "largest RCODE",
			data: []byte{0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{RCode: 15},
		},
		{
			name: "counts are big-endian and in QD, AN, NS, AR order",
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want: Header{QDCount: 0x0102, ANCount: 0x0304, NSCount: 0x0506, ARCount: 0x0708},
		},
		{
			name: "every bit set",
			data: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			want: Header{
				ID: 0xFFFF, QR: true, Opcode: 15, AA: true, TC: true, RD: true, RA: true, Z: 7, RCode: 15,
				QDCount: 0xFFFF, ANCount: 0xFFFF, NSCount: 0xFFFF, ARCount: 0xFFFF,
			},
		},
		{
			name: "a mix of fields",
			data: []byte{0xBE, 0xEF, 0x91, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04},
			want: Header{
				ID: 0xBEEF, QR: true, Opcode: 2, RD: true, RCode: 4,
				QDCount: 1, ANCount: 2, NSCount: 3, ARCount: 4,
			},
		},
		{
			name: "bytes after the header are ignored",
			data: []byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
			want: Header{ID: 1234, RD: true, QDCount: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeader(tt.data)
			if err != nil {
				t.Fatalf("parseHeader returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseHeaderRejectsShortInput(t *testing.T) {
	full := []byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Every length from nothing at all up to one byte short of a header.
	for length := 0; length < headerSize; length++ {
		if got, err := parseHeader(full[:length]); err == nil {
			t.Errorf("parseHeader of %d bytes = %+v, want an error", length, got)
		}
	}

	if got, err := parseHeader(nil); err == nil {
		t.Errorf("parseHeader(nil) = %+v, want an error", got)
	}
}

// Parsing must be the exact inverse of encoding for every possible value of
// the flags word, so that no bit is lost or moved on the way through.
func TestParseHeaderRoundTripsEveryFlagsWord(t *testing.T) {
	for flags := 0; flags <= 0xFFFF; flags++ {
		data := []byte{0x12, 0x34, byte(flags >> 8), byte(flags), 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04}

		header, err := parseHeader(data)
		if err != nil {
			t.Fatalf("flags %#04x: parseHeader returned an error: %v", flags, err)
		}

		if got := header.appendTo(nil); !bytes.Equal(got, data) {
			t.Fatalf("flags %#04x: parsed as %+v, which encodes back to % x, want % x", flags, header, got, data)
		}
	}
}

func TestAppendName(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   []byte
	}{
		{
			name:   "two labels",
			domain: "google.com",
			want:   []byte("\x06google\x03com\x00"),
		},
		{
			name:   "matches the hex dump in the stage instructions",
			domain: "google.com",
			want:   []byte{0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00},
		},
		{
			name:   "codecrafters.io",
			domain: "codecrafters.io",
			want:   []byte("\x0ccodecrafters\x02io\x00"),
		},
		{
			name:   "single label",
			domain: "localhost",
			want:   []byte("\x09localhost\x00"),
		},
		{
			name:   "many labels",
			domain: "a.bc.def.example.com",
			want:   []byte("\x01a\x02bc\x03def\x07example\x03com\x00"),
		},
		{
			name:   "trailing dot is ignored",
			domain: "codecrafters.io.",
			want:   []byte("\x0ccodecrafters\x02io\x00"),
		},
		{
			name:   "empty name is the root",
			domain: "",
			want:   []byte{0x00},
		},
		{
			name:   "lone dot is the root",
			domain: ".",
			want:   []byte{0x00},
		},
		{
			name:   "case is preserved",
			domain: "CodeCrafters.IO",
			want:   []byte("\x0cCodeCrafters\x02IO\x00"),
		},
		{
			name:   "label of the maximum length",
			domain: strings.Repeat("a", 63) + ".com",
			want:   []byte("\x3f" + strings.Repeat("a", 63) + "\x03com\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appendName(nil, tt.domain)
			if err != nil {
				t.Fatalf("appendName(nil, %q) returned an error: %v", tt.domain, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("appendName(nil, %q) = % x, want % x", tt.domain, got, tt.want)
			}
		})
	}
}

func TestAppendNameEscapes(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   []byte
	}{
		{
			name:   "escaped dot is part of the label",
			domain: `first\.last.example.com`,
			want:   []byte("\x0afirst.last\x07example\x03com\x00"),
		},
		{
			name:   "escaped backslash",
			domain: `a\\b.com`,
			want:   []byte("\x03a\\b\x03com\x00"),
		},
		{
			name:   "escaped ordinary character stands for itself",
			domain: `\a\b.com`,
			want:   []byte("\x02ab\x03com\x00"),
		},
		{
			name:   "decimal escape",
			domain: `\065\066.com`,
			want:   []byte("\x02AB\x03com\x00"),
		},
		{
			name:   "decimal escape for a dot",
			domain: `a\046b.com`,
			want:   []byte("\x03a.b\x03com\x00"),
		},
		{
			name:   "smallest and largest decimal escapes",
			domain: `\000\255.com`,
			want:   []byte("\x02\x00\xff\x03com\x00"),
		},
		{
			name:   "decimal escape followed by a digit",
			domain: `\0657.com`,
			want:   []byte("\x02A7\x03com\x00"),
		},
		{
			name:   "escaped dot at the end is not a trailing dot",
			domain: `a\.`,
			want:   []byte("\x02a.\x00"),
		},
		{
			name:   "escaped backslash followed by a trailing dot",
			domain: `a\\.`,
			want:   []byte("\x02a\\\x00"),
		},
		{
			name:   "label that is nothing but an escaped dot",
			domain: `\.`,
			want:   []byte("\x01.\x00"),
		},
		{
			name:   "escapes count as one byte towards the label length",
			domain: strings.Repeat(`\.`, 63) + ".com",
			want:   []byte("\x3f" + strings.Repeat(".", 63) + "\x03com\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appendName(nil, tt.domain)
			if err != nil {
				t.Fatalf("appendName(nil, %q) returned an error: %v", tt.domain, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("appendName(nil, %q) = % x, want % x", tt.domain, got, tt.want)
			}
		})
	}
}

func TestAppendNameRejectsInvalidEscapes(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "backslash at the end", domain: `example.com\`},
		{name: "lone backslash", domain: `\`},
		{name: "decimal escape of one digit", domain: `\1.com`},
		{name: "decimal escape of two digits", domain: `\12.com`},
		{name: "decimal escape of two digits at the end", domain: `a.\12`},
		{name: "decimal escape with a letter in it", domain: `\1a2.com`},
		// The characters next to the digits in ASCII: taken for digits, they
		// would add up to a value that passes for a byte.
		{name: "decimal escape with a slash for its second digit", domain: `\0/0.com`},
		{name: "decimal escape with a colon for its second digit", domain: `\0:0.com`},
		{name: "decimal escape with a slash for its third digit", domain: `\00/.com`},
		{name: "decimal escape with a colon for its third digit", domain: `\00:.com`},
		{name: "decimal escape just above a byte", domain: `\256.com`},
		{name: "largest decimal escape", domain: `\999.com`},
		{name: "label of escapes one byte over the limit", domain: strings.Repeat(`\.`, 64) + ".com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := appendName(nil, tt.domain); err == nil {
				t.Errorf("appendName(nil, %q) = % x, want an error", tt.domain, got)
			}
		})
	}
}

func TestAppendNameKeepsExistingBytes(t *testing.T) {
	prefix := []byte{0xAA, 0xBB}

	got, err := appendName(prefix, "a.io")
	if err != nil {
		t.Fatalf("appendName returned an error: %v", err)
	}

	want := []byte("\xAA\xBB\x01a\x02io\x00")

	if !bytes.Equal(got, want) {
		t.Errorf("appendName(prefix, \"a.io\") = % x, want % x", got, want)
	}
}

func TestAppendNameLongestName(t *testing.T) {
	// Three 63-byte labels and one 61-byte label take 3*64 + 62 bytes, plus
	// the terminating zero byte: exactly the 255-byte limit.
	label := strings.Repeat("a", 63)
	domain := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".")

	got, err := appendName(nil, domain)
	if err != nil {
		t.Fatalf("appendName returned an error for a name of the maximum length: %v", err)
	}
	if len(got) != maxNameLength {
		t.Errorf("encoded name is %d bytes, want %d", len(got), maxNameLength)
	}
}

func TestAppendNameRejectsInvalidNames(t *testing.T) {
	label := strings.Repeat("a", 63)

	tests := []struct {
		name   string
		domain string
	}{
		{name: "label one byte over the limit", domain: strings.Repeat("a", 64) + ".com"},
		{name: "empty label in the middle", domain: "codecrafters..io"},
		{name: "empty leading label", domain: ".codecrafters.io"},
		{name: "two trailing dots", domain: "codecrafters.io.."},
		{name: "only dots", domain: ".."},
		{
			// One byte longer than the name in TestAppendNameLongestName.
			name:   "name one byte over the limit",
			domain: strings.Join([]string{label, label, label, strings.Repeat("b", 62)}, "."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appendName(nil, tt.domain)
			if err == nil {
				t.Errorf("appendName(nil, %q) = % x, want an error", tt.domain, got)
			}
		})
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		want     string
		wantNext int
	}{
		{
			name:     "two labels",
			data:     []byte("\x06google\x03com\x00"),
			want:     "google.com",
			wantNext: 12,
		},
		{
			name:     "codecrafters.io",
			data:     []byte("\x0ccodecrafters\x02io\x00"),
			want:     "codecrafters.io",
			wantNext: 17,
		},
		{
			name:     "single label",
			data:     []byte("\x09localhost\x00"),
			want:     "localhost",
			wantNext: 11,
		},
		{
			name:     "many labels",
			data:     []byte("\x01a\x02bc\x03def\x07example\x03com\x00"),
			want:     "a.bc.def.example.com",
			wantNext: 22,
		},
		{
			name:     "root",
			data:     []byte{0x00},
			want:     ".",
			wantNext: 1,
		},
		{
			name:     "case is preserved",
			data:     []byte("\x0cCodeCrafters\x02IO\x00"),
			want:     "CodeCrafters.IO",
			wantNext: 17,
		},
		{
			name:     "bytes that are not letters are preserved",
			data:     []byte("\x04a\x00\xffb\x03c d\x00"),
			want:     "a\x00\xffb.c d",
			wantNext: 10,
		},
		{
			name:     "name in the middle of the data",
			data:     []byte("\xAA\xBB\x01a\x02io\x00\xCC\xDD"),
			offset:   2,
			want:     "a.io",
			wantNext: 8,
		},
		{
			name:     "label of the maximum length",
			data:     []byte("\x3f" + strings.Repeat("a", 63) + "\x03com\x00"),
			want:     strings.Repeat("a", 63) + ".com",
			wantNext: 69,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseName(tt.data, tt.offset)
			if err != nil {
				t.Fatalf("parseName returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseName() name = %q, want %q", got, tt.want)
			}
			if next != tt.wantNext {
				t.Errorf("parseName() next offset = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

func TestParseNameFollowsCompressionPointers(t *testing.T) {
	// Offsets of the names in message:
	//
	//	 0  abc.longassdomainname.com, written out in full
	//	27  def + pointer to offset 4 (longassdomainname.com)
	//	33  pointer to offset 0 (abc.longassdomainname.com)
	//	35  ghi + pointer to offset 27, which itself ends with a pointer
	//	41  www + pointer to offset 22 (com)
	//	47  pointer to offset 26, the zero byte that ends the first name
	//	49  xyz + pointer to offset 26
	//	55  pointer to offset 33, which is itself a pointer
	//	57  end of the message
	message := concat(
		[]byte("\x03abc\x11longassdomainname\x03com\x00"),
		[]byte("\x03def\xC0\x04"),
		[]byte("\xC0\x00"),
		[]byte("\x03ghi\xC0\x1B"),
		[]byte("\x03www\xC0\x16"),
		[]byte("\xC0\x1A"),
		[]byte("\x03xyz\xC0\x1A"),
		[]byte("\xC0\x21"),
	)

	tests := []struct {
		name     string
		offset   int
		want     string
		wantNext int
	}{
		{name: "no pointer", offset: 0, want: "abc.longassdomainname.com", wantNext: 27},
		{name: "labels followed by a pointer", offset: 27, want: "def.longassdomainname.com", wantNext: 33},
		{name: "pointer on its own", offset: 33, want: "abc.longassdomainname.com", wantNext: 35},
		{name: "pointer to a name that ends with a pointer", offset: 35, want: "ghi.def.longassdomainname.com", wantNext: 41},
		{name: "pointer to the last label of a name", offset: 41, want: "www.com", wantNext: 47},
		{name: "pointer to the end of a name is the root", offset: 47, want: ".", wantNext: 49},
		{name: "labels followed by a pointer to the end of a name", offset: 49, want: "xyz", wantNext: 55},
		{name: "pointer to a pointer", offset: 55, want: "abc.longassdomainname.com", wantNext: 57},
		{name: "name that starts in the middle of another", offset: 4, want: "longassdomainname.com", wantNext: 27},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseName(message, tt.offset)
			if err != nil {
				t.Fatalf("parseName returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseName() name = %q, want %q", got, tt.want)
			}
			if next != tt.wantNext {
				t.Errorf("parseName() next offset = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

func TestParseNamePointerUsesAll14BitsOfItsOffset(t *testing.T) {
	// A name at offset 0x0123, which needs bits from both bytes of a pointer.
	message := make([]byte, 0x0123)
	message = append(message, "\x01a\x02io\x00"...)
	message = append(message, 0xC1, 0x23)

	got, next, err := parseName(message, 0x0123+6)
	if err != nil {
		t.Fatalf("parseName returned an error: %v", err)
	}
	if got != "a.io" {
		t.Errorf("parseName() name = %q, want %q", got, "a.io")
	}
	if want := 0x0123 + 8; next != want {
		t.Errorf("parseName() next offset = %d, want %d", next, want)
	}
}

func TestParseNameRejectsInvalidCompressionPointers(t *testing.T) {
	label := "\x3f" + strings.Repeat("a", 63)

	tests := []struct {
		name   string
		data   []byte
		offset int
	}{
		{name: "pointer to itself", data: []byte("\xC0\x00")},
		{name: "pointer to itself after other data", data: []byte("\x01a\x00\xC0\x03"), offset: 3},
		{name: "pointer to the labels it follows", data: []byte("\x01a\xC0\x00")},
		{name: "pointer to the middle of the labels it follows", data: []byte("\x01a\x01b\xC0\x02")},
		{name: "pointer forwards", data: []byte("\xC0\x02\x01a\x00")},
		{name: "pointer past the end of the message", data: []byte("\x01a\x00\xC0\x7F"), offset: 3},
		{name: "two pointers to each other", data: []byte("\xC0\x02\xC0\x00"), offset: 2},
		{
			// The second name points back to the first, whose labels run on
			// into the second name and its pointer.
			name:   "loop through an earlier name",
			data:   []byte("\x01a\x01b\xC0\x00"),
			offset: 2,
		},
		{name: "pointer cut short", data: []byte("\x01a\x00\xC0"), offset: 3},
		{name: "pointer cut short after labels", data: []byte("\x01a\xC0")},
		{name: "pointer to a truncated name", data: []byte("\x05ab\xC0\x00"), offset: 3},
		{name: "pointer to a reserved label type", data: []byte("\x80a\x00\xC0\x00"), offset: 3},
		{
			// The first name is as long as a name may be, so anything in
			// front of a pointer to it is too much.
			name:   "pointer that makes the name too long",
			data:   []byte(label + label + label + "\x3d" + strings.Repeat("b", 61) + "\x00" + "\x01c\xC0\x00"),
			offset: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, next, err := parseName(tt.data, tt.offset); err == nil {
				t.Errorf("parseName() = %q with next offset %d, want an error", got, next)
			}
		})
	}
}

func TestParseNameEscapesDotsAndBackslashesInLabels(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "dot in a label", data: []byte("\x0afirst.last\x07example\x03com\x00"), want: `first\.last.example.com`},
		{name: "backslash in a label", data: []byte("\x03a\\b\x03com\x00"), want: `a\\b.com`},
		{name: "label that is a dot", data: []byte("\x01.\x00"), want: `\.`},
		{name: "label that ends with a dot", data: []byte("\x02a.\x00"), want: `a\.`},
		{name: "label that ends with a backslash", data: []byte("\x02a\\\x03com\x00"), want: `a\\.com`},
		{name: "backslash followed by digits", data: []byte("\x04\\065\x00"), want: `\\065`},
		{name: "dot followed by digits", data: []byte("\x04.065\x00"), want: `\.065`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseName(tt.data, 0)
			if err != nil {
				t.Fatalf("parseName returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseName() name = %q, want %q", got, tt.want)
			}
			if next != len(tt.data) {
				t.Errorf("parseName() next offset = %d, want %d", next, len(tt.data))
			}

			// The name has to encode back to exactly the same labels.
			encoded, err := appendName(nil, got)
			if err != nil {
				t.Fatalf("appendName(nil, %q) returned an error: %v", got, err)
			}
			if !bytes.Equal(encoded, tt.data) {
				t.Errorf("%q encodes back to % x, want % x", got, encoded, tt.data)
			}
		})
	}
}

// A label may hold any byte at all, and every one of them has to come out of
// a trip through the text form of a name unchanged.
func TestParseNameRoundTripsEveryByteValue(t *testing.T) {
	for value := 0; value <= 0xFF; value++ {
		wire := []byte{0x03, 'a', byte(value), 'b', 0x02, byte(value), byte(value), 0x01, byte(value), 0x00}

		name, next, err := parseName(wire, 0)
		if err != nil {
			t.Fatalf("byte %#02x: parseName returned an error: %v", value, err)
		}
		if next != len(wire) {
			t.Errorf("byte %#02x: next offset = %d, want %d", value, next, len(wire))
		}

		encoded, err := appendName(nil, name)
		if err != nil {
			t.Fatalf("byte %#02x: appendName(nil, %q) returned an error: %v", value, name, err)
		}
		if !bytes.Equal(encoded, wire) {
			t.Errorf("byte %#02x: decoded as %q, which encodes back to % x, want % x", value, name, encoded, wire)
		}
	}
}

func TestParseNameCountsEscapedBytesOnceTowardsLengthLimit(t *testing.T) {
	// A name of the maximum length made of nothing but dots, each of which
	// takes two bytes in the text form of the name.
	label := "\x3f" + strings.Repeat(".", 63)
	wire := []byte(label + label + label + "\x3d" + strings.Repeat(".", 61) + "\x00")

	name, _, err := parseName(wire, 0)
	if err != nil {
		t.Fatalf("parseName returned an error for a name of the maximum length: %v", err)
	}

	encoded, err := appendName(nil, name)
	if err != nil {
		t.Fatalf("appendName returned an error: %v", err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Errorf("name encodes back to % x, want % x", encoded, wire)
	}
}

func TestParseNameLongestName(t *testing.T) {
	// Three 63-byte labels and one 61-byte label: exactly 255 bytes encoded.
	label := strings.Repeat("a", 63)
	want := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".")

	data, err := appendName(nil, want)
	if err != nil {
		t.Fatalf("appendName returned an error: %v", err)
	}

	got, next, err := parseName(data, 0)
	if err != nil {
		t.Fatalf("parseName returned an error for a name of the maximum length: %v", err)
	}
	if got != want {
		t.Errorf("parseName() name = %q, want %q", got, want)
	}
	if next != maxNameLength {
		t.Errorf("parseName() next offset = %d, want %d", next, maxNameLength)
	}
}

func TestParseNameRejectsInvalidNames(t *testing.T) {
	label := "\x3f" + strings.Repeat("a", 63)

	tests := []struct {
		name   string
		data   []byte
		offset int
	}{
		{name: "no data", data: nil},
		{name: "offset at the end of the data", data: []byte("\x01a\x00"), offset: 3},
		{name: "offset past the end of the data", data: []byte("\x01a\x00"), offset: 9},
		{name: "missing terminator", data: []byte("\x06google\x03com")},
		{name: "label cut short", data: []byte("\x06goo")},
		{name: "label length without any content", data: []byte("\x06")},
		{name: "label type 01 is reserved", data: []byte("\x40a\x00")},
		{name: "label type 10 is reserved", data: []byte("\x80a\x00")},
		{
			// Read as a length, 0x40 would be a 64-byte label, one byte too long.
			name: "label type 01 followed by as many bytes as it would count",
			data: []byte("\x40" + strings.Repeat("a", 64) + "\x00"),
		},
		{
			name: "label type 10 followed by as many bytes as it would count",
			data: []byte("\x80" + strings.Repeat("a", 128) + "\x00"),
		},
		{
			name: "largest value of label type 10 followed by as many bytes as it would count",
			data: []byte("\xBF" + strings.Repeat("a", 191) + "\x00"),
		},
		{
			// 4*64 + 1 = 257 bytes encoded, two more than the limit.
			name: "name over the length limit",
			data: []byte(label + label + label + label + "\x00"),
		},
		{
			// 3*64 + 63 + 1 = 256 bytes encoded, one more than the limit.
			name: "name one byte over the length limit",
			data: []byte(label + label + label + "\x3e" + strings.Repeat("b", 62) + "\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, next, err := parseName(tt.data, tt.offset); err == nil {
				t.Errorf("parseName() = %q with next offset %d, want an error", got, next)
			}
		})
	}
}

// Every name that can be encoded must decode to itself.
func TestParseNameRoundTrip(t *testing.T) {
	names := []string{
		".",
		"io",
		"codecrafters.io",
		"abc.longassdomainname.com",
		"CodeCrafters.IO",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z",
		"xn--bcher-kva.example",
		"_dmarc.example.com",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63),
	}

	for _, name := range names {
		data, err := appendName(nil, name)
		if err != nil {
			t.Errorf("appendName(nil, %q) returned an error: %v", name, err)
			continue
		}

		got, next, err := parseName(data, 0)
		if err != nil {
			t.Errorf("parseName of the encoding of %q returned an error: %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("%q decoded as %q", name, got)
		}
		if next != len(data) {
			t.Errorf("%q: next offset = %d, want %d", name, next, len(data))
		}
	}
}

func TestParseQuestion(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		want     Question
		wantNext int
	}{
		{
			name:     "A record of codecrafters.io",
			data:     []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
			want:     Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
			wantNext: 21,
		},
		{
			name:     "type and class are big-endian",
			data:     []byte("\x01a\x02io\x00\x01\x02\x03\x04"),
			want:     Question{Name: "a.io", Type: 0x0102, Class: 0x0304},
			wantNext: 10,
		},
		{
			name:     "root name",
			data:     []byte{0x00, 0x00, 0x02, 0x00, 0x01},
			want:     Question{Name: ".", Type: 2, Class: ClassIN},
			wantNext: 5,
		},
		{
			name:     "question in the middle of the data",
			data:     []byte("\xAA\xBB\xCC\x01a\x02io\x00\x00\x01\x00\x01\xDD"),
			offset:   3,
			want:     Question{Name: "a.io", Type: TypeA, Class: ClassIN},
			wantNext: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseQuestion(tt.data, tt.offset)
			if err != nil {
				t.Fatalf("parseQuestion returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseQuestion() = %+v, want %+v", got, tt.want)
			}
			if next != tt.wantNext {
				t.Errorf("parseQuestion() next offset = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

func TestParseQuestionRejectsInvalidQuestions(t *testing.T) {
	full := []byte("\x01a\x02io\x00\x00\x01\x00\x01")

	// Every way of cutting the question short, from nothing to one byte missing.
	for length := 0; length < len(full); length++ {
		if got, _, err := parseQuestion(full[:length], 0); err == nil {
			t.Errorf("parseQuestion of the first %d bytes = %+v, want an error", length, got)
		}
	}

	if got, _, err := parseQuestion([]byte("\x40a\x00\x00\x01\x00\x01"), 0); err == nil {
		t.Errorf("parseQuestion with an invalid name = %+v, want an error", got)
	}
}

func TestQuestionAppendTo(t *testing.T) {
	tests := []struct {
		name     string
		question Question
		want     []byte
	}{
		{
			name:     "A record of codecrafters.io",
			question: Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
			want:     []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
		},
		{
			name:     "type and class are big-endian",
			question: Question{Name: "a.io", Type: 0x0102, Class: 0x0304},
			want:     []byte("\x01a\x02io\x00\x01\x02\x03\x04"),
		},
		{
			name:     "root name",
			question: Question{Name: ".", Type: 2, Class: ClassIN},
			want:     []byte{0x00, 0x00, 0x02, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.question.appendTo(nil)
			if err != nil {
				t.Fatalf("appendTo(nil) returned an error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("appendTo(nil) = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestQuestionAppendToRejectsInvalidName(t *testing.T) {
	question := Question{Name: "codecrafters..io", Type: TypeA, Class: ClassIN}

	if got, err := question.appendTo(nil); err == nil {
		t.Errorf("appendTo(nil) = % x, want an error", got)
	}
}

func TestResourceRecordAppendTo(t *testing.T) {
	tests := []struct {
		name   string
		record ResourceRecord
		want   []byte
	}{
		{
			name:   "A record of codecrafters.io",
			record: ResourceRecord{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			want: concat(
				[]byte("\x0ccodecrafters\x02io\x00"),
				[]byte{0x00, 0x01},             // TYPE: A
				[]byte{0x00, 0x01},             // CLASS: IN
				[]byte{0x00, 0x00, 0x00, 0x3C}, // TTL: 60
				[]byte{0x00, 0x04},             // RDLENGTH: 4
				[]byte{0x08, 0x08, 0x08, 0x08}, // RDATA: 8.8.8.8
			),
		},
		{
			name:   "type, class and TTL are big-endian",
			record: ResourceRecord{Name: "a.io", Type: 0x0102, Class: 0x0304, TTL: 0x05060708, Data: []byte{0xFF}},
			want: concat(
				[]byte("\x01a\x02io\x00"),
				[]byte{0x01, 0x02},
				[]byte{0x03, 0x04},
				[]byte{0x05, 0x06, 0x07, 0x08},
				[]byte{0x00, 0x01},
				[]byte{0xFF},
			),
		},
		{
			name:   "largest TTL",
			record: ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 0xFFFFFFFF, Data: []byte{1, 2, 3, 4}},
			want: concat(
				[]byte("\x01a\x02io\x00"),
				[]byte{0x00, 0x01},
				[]byte{0x00, 0x01},
				[]byte{0xFF, 0xFF, 0xFF, 0xFF},
				[]byte{0x00, 0x04},
				[]byte{0x01, 0x02, 0x03, 0x04},
			),
		},
		{
			name:   "RDLENGTH is zero without data",
			record: ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1},
			want: concat(
				[]byte("\x01a\x02io\x00"),
				[]byte{0x00, 0x01},
				[]byte{0x00, 0x01},
				[]byte{0x00, 0x00, 0x00, 0x01},
				[]byte{0x00, 0x00},
			),
		},
		{
			name:   "RDLENGTH is big-endian",
			record: ResourceRecord{Name: "", Type: 16, Class: ClassIN, Data: bytes.Repeat([]byte{0xAB}, 0x0102)},
			want: concat(
				[]byte{0x00},
				[]byte{0x00, 0x10},
				[]byte{0x00, 0x01},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0x01, 0x02},
				bytes.Repeat([]byte{0xAB}, 0x0102),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.record.appendTo(nil)
			if err != nil {
				t.Fatalf("appendTo(nil) returned an error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("appendTo(nil) = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestResourceRecordAppendToKeepsExistingBytes(t *testing.T) {
	prefix := []byte{0xAA, 0xBB}
	record := ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}}

	got, err := record.appendTo(prefix)
	if err != nil {
		t.Fatalf("appendTo(prefix) returned an error: %v", err)
	}

	want := []byte("\xAA\xBB\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08")

	if !bytes.Equal(got, want) {
		t.Errorf("appendTo(prefix) = % x, want % x", got, want)
	}
}

func TestResourceRecordAppendToLargestData(t *testing.T) {
	record := ResourceRecord{Name: "a.io", Type: 16, Class: ClassIN, Data: make([]byte, 65535)}

	got, err := record.appendTo(nil)
	if err != nil {
		t.Fatalf("appendTo(nil) returned an error for data of the maximum length: %v", err)
	}

	// name (6) + type (2) + class (2) + TTL (4) precede RDLENGTH.
	if rdlength := got[14:16]; !bytes.Equal(rdlength, []byte{0xFF, 0xFF}) {
		t.Errorf("RDLENGTH = % x, want ff ff", rdlength)
	}
	if len(got) != 16+65535 {
		t.Errorf("encoded record is %d bytes, want %d", len(got), 16+65535)
	}
}

func TestResourceRecordAppendToRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name   string
		record ResourceRecord
	}{
		{
			name:   "data one byte over what RDLENGTH can count",
			record: ResourceRecord{Name: "a.io", Type: 16, Class: ClassIN, Data: make([]byte, 65536)},
		},
		{
			name:   "invalid name",
			record: ResourceRecord{Name: "a..io", Type: TypeA, Class: ClassIN, Data: []byte{8, 8, 8, 8}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := tt.record.appendTo(nil); err == nil {
				t.Errorf("appendTo(nil) returned %d bytes, want an error", len(got))
			}
		})
	}
}

func TestParseResourceRecord(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		want     ResourceRecord
		wantNext int
	}{
		{
			name:     "A record of codecrafters.io",
			data:     []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08"),
			want:     ResourceRecord{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			wantNext: 31,
		},
		{
			name:     "type, class and TTL are big-endian",
			data:     []byte("\x01a\x02io\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x01\xFF"),
			want:     ResourceRecord{Name: "a.io", Type: 0x0102, Class: 0x0304, TTL: 0x05060708, Data: []byte{0xFF}},
			wantNext: 17,
		},
		{
			name:     "largest TTL",
			data:     []byte("\x01a\x02io\x00\x00\x01\x00\x01\xFF\xFF\xFF\xFF\x00\x04\x01\x02\x03\x04"),
			want:     ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 0xFFFFFFFF, Data: []byte{1, 2, 3, 4}},
			wantNext: 20,
		},
		{
			name:     "no data",
			data:     []byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x00"),
			want:     ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{}},
			wantNext: 16,
		},
		{
			name:     "RDLENGTH is big-endian",
			data:     concat([]byte("\x00\x00\x10\x00\x01\x00\x00\x00\x00\x01\x02"), bytes.Repeat([]byte{0xAB}, 0x0102)),
			want:     ResourceRecord{Name: ".", Type: 16, Class: ClassIN, Data: bytes.Repeat([]byte{0xAB}, 0x0102)},
			wantNext: 11 + 0x0102,
		},
		{
			name:     "compressed name",
			data:     []byte("\x01a\x02io\x00\xC0\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08"),
			offset:   6,
			want:     ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			wantNext: 22,
		},
		{
			name:     "record in the middle of the data",
			data:     []byte("\xAA\xBB\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08\xCC"),
			offset:   2,
			want:     ResourceRecord{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			wantNext: 22,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseResourceRecord(tt.data, tt.offset)
			if err != nil {
				t.Fatalf("parseResourceRecord returned an error: %v", err)
			}
			if got.Name != tt.want.Name || got.Type != tt.want.Type || got.Class != tt.want.Class || got.TTL != tt.want.TTL {
				t.Errorf("parseResourceRecord() = %+v, want %+v", got, tt.want)
			}
			if !bytes.Equal(got.Data, tt.want.Data) {
				t.Errorf("parseResourceRecord() data = % x, want % x", got.Data, tt.want.Data)
			}
			if next != tt.wantNext {
				t.Errorf("parseResourceRecord() next offset = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

func TestParseResourceRecordCopiesData(t *testing.T) {
	data := []byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08")

	record, _, err := parseResourceRecord(data, 0)
	if err != nil {
		t.Fatalf("parseResourceRecord returned an error: %v", err)
	}

	// The buffer a packet was read into is reused for the next packet.
	for i := range data {
		data[i] = 0xEE
	}

	if want := []byte{8, 8, 8, 8}; !bytes.Equal(record.Data, want) {
		t.Errorf("record data changed to % x along with the message it was read from", record.Data)
	}
}

func TestParseResourceRecordRejectsInvalidRecords(t *testing.T) {
	full := []byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08")

	// Every way of cutting the record short, from nothing to one byte missing.
	for length := 0; length < len(full); length++ {
		if got, _, err := parseResourceRecord(full[:length], 0); err == nil {
			t.Errorf("parseResourceRecord of the first %d bytes = %+v, want an error", length, got)
		}
	}

	if got, _, err := parseResourceRecord([]byte("\x40a\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x00"), 0); err == nil {
		t.Errorf("parseResourceRecord with an invalid name = %+v, want an error", got)
	}
}

func TestParseResourceRecordExpandsCompressedNamesInData(t *testing.T) {
	// A message body that the records below point into:
	//
	//	 0  www.example.com
	//	17  mail.example.com, as mail + pointer to offset 4 (example.com)
	const prefix = "\x03www\x07example\x03com\x00" + "\x04mail\xC0\x04"

	// Everything up to the data of a record: the root as its name, then
	// type, class, TTL and RDLENGTH.
	record := func(recordType uint16, data string) []byte {
		fields := []byte{0x00, byte(recordType >> 8), byte(recordType), 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, byte(len(data))}
		return concat([]byte(prefix), fields, []byte(data))
	}

	soaNumbers := "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"

	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "CNAME that is a pointer",
			data: record(TypeCNAME, "\xC0\x00"),
			want: []byte("\x03www\x07example\x03com\x00"),
		},
		{
			name: "CNAME that ends with a pointer",
			data: record(TypeCNAME, "\x03web\xC0\x04"),
			want: []byte("\x03web\x07example\x03com\x00"),
		},
		{
			name: "CNAME that points to a name that ends with a pointer",
			data: record(TypeCNAME, "\xC0\x11"),
			want: []byte("\x04mail\x07example\x03com\x00"),
		},
		{
			name: "CNAME that is not compressed",
			data: record(TypeCNAME, "\x03web\x07example\x03org\x00"),
			want: []byte("\x03web\x07example\x03org\x00"),
		},
		{
			name: "CNAME that is the root",
			data: record(TypeCNAME, "\x00"),
			want: []byte("\x00"),
		},
		{
			name: "NS",
			data: record(TypeNS, "\x03ns1\xC0\x04"),
			want: []byte("\x03ns1\x07example\x03com\x00"),
		},
		{
			name: "PTR",
			data: record(TypePTR, "\xC0\x11"),
			want: []byte("\x04mail\x07example\x03com\x00"),
		},
		{
			name: "MX keeps its preference in front of the name",
			data: record(TypeMX, "\x00\x0A\xC0\x11"),
			want: []byte("\x00\x0A\x04mail\x07example\x03com\x00"),
		},
		{
			name: "SOA expands both names and keeps its numbers",
			data: record(TypeSOA, "\x03ns1\xC0\x04"+"\x0afirst.last\xC0\x04"+soaNumbers),
			want: []byte("\x03ns1\x07example\x03com\x00" + "\x0afirst.last\x07example\x03com\x00" + soaNumbers),
		},
		{
			name: "MINFO expands both names",
			data: record(14, "\xC0\x00\xC0\x11"),
			want: []byte("\x03www\x07example\x03com\x00" + "\x04mail\x07example\x03com\x00"),
		},
		{
			name: "MB, one of the obsolete types",
			data: record(7, "\xC0\x11"),
			want: []byte("\x04mail\x07example\x03com\x00"),
		},
		{
			name: "A is kept as it is, even if it looks like a pointer",
			data: record(TypeA, "\xC0\x00\xC0\x04"),
			want: []byte("\xC0\x00\xC0\x04"),
		},
		{
			name: "TXT is kept as it is, even if it looks like a pointer",
			data: record(16, "\x05\xC0\x00\xC0\x04!"),
			want: []byte("\x05\xC0\x00\xC0\x04!"),
		},
		{
			name: "SRV is kept as it is: its name may not be compressed",
			data: record(33, "\x00\x01\x00\x02\x01\xBB\x03sip\x07example\x03com\x00"),
			want: []byte("\x00\x01\x00\x02\x01\xBB\x03sip\x07example\x03com\x00"),
		},
		{
			name: "unknown type is kept as it is",
			data: record(65280, "\xC0\x00\x01\x02"),
			want: []byte("\xC0\x00\x01\x02"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := parseResourceRecord(tt.data, len(prefix))
			if err != nil {
				t.Fatalf("parseResourceRecord returned an error: %v", err)
			}
			if !bytes.Equal(got.Data, tt.want) {
				t.Errorf("parseResourceRecord() data = % x, want % x", got.Data, tt.want)
			}
			if next != len(tt.data) {
				t.Errorf("parseResourceRecord() next offset = %d, want %d", next, len(tt.data))
			}
		})
	}
}

func TestParseResourceRecordRejectsInvalidDataOfTypesWithNames(t *testing.T) {
	const prefix = "\x03www\x07example\x03com\x00"

	record := func(recordType uint16, rdlength int, data string) []byte {
		fields := []byte{0x00, byte(recordType >> 8), byte(recordType), 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, byte(rdlength)}
		return concat([]byte(prefix), fields, []byte(data))
	}

	soaNumbers := "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"

	tests := []struct {
		name string
		data []byte
	}{
		{name: "CNAME without data", data: record(TypeCNAME, 0, "")},
		{name: "CNAME cut short by RDLENGTH", data: record(TypeCNAME, 3, "\x03web\xC0\x04")},
		{name: "CNAME that runs past RDLENGTH into what follows", data: record(TypeCNAME, 4, "\x03web\xC0\x04")},
		{name: "CNAME with bytes after its name", data: record(TypeCNAME, 3, "\xC0\x00\x00")},
		{name: "CNAME with two names", data: record(TypeCNAME, 4, "\xC0\x00\xC0\x04")},
		{name: "CNAME with a pointer to itself", data: record(TypeCNAME, 2, "\xC0\x1C")},
		{name: "CNAME with a pointer forwards", data: record(TypeCNAME, 2, "\xC0\x30")},
		{name: "CNAME with a reserved label type", data: record(TypeCNAME, 3, "\x80a\x00")},
		{name: "MX without a name", data: record(TypeMX, 2, "\x00\x0A")},
		{name: "MX with half a preference", data: record(TypeMX, 1, "\x00")},
		{name: "MX with bytes after its name", data: record(TypeMX, 5, "\x00\x0A\xC0\x00\x00")},
		{name: "SOA with one name", data: record(TypeSOA, 2, "\xC0\x00")},
		{name: "SOA without its numbers", data: record(TypeSOA, 4, "\xC0\x00\xC0\x04")},
		{name: "SOA with a number missing", data: record(TypeSOA, 20, "\xC0\x00\xC0\x04"+soaNumbers[:16])},
		{name: "SOA with a byte too many", data: record(TypeSOA, 25, "\xC0\x00\xC0\x04"+soaNumbers+"\x00")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _, err := parseResourceRecord(tt.data, len(prefix)); err == nil {
				t.Errorf("parseResourceRecord() = %+v, want an error", got)
			}
		})
	}
}

func TestMessageEncode(t *testing.T) {
	tests := []struct {
		name    string
		message Message
		want    []byte
	}{
		{
			name:    "header only",
			message: Message{Header: Header{ID: 1234, QR: true}},
			want:    []byte{0x04, 0xD2, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "header and one question",
			message: Message{
				Header:    Header{ID: 1234, QR: true},
				Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
			},
			want: concat(
				[]byte{0x04, 0xD2, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
			),
		},
		{
			name: "questions are encoded in order",
			message: Message{
				Header: Header{ID: 0xBEEF},
				Questions: []Question{
					{Name: "a.io", Type: TypeA, Class: ClassIN},
					{Name: "b.io", Type: 5, Class: ClassIN},
				},
			},
			want: concat(
				[]byte{0xBE, 0xEF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x01b\x02io\x00\x00\x05\x00\x01"),
			),
		},
		{
			name: "QDCOUNT comes from the questions, not from the header",
			message: Message{
				Header:    Header{ID: 1, QDCount: 7},
				Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
			},
			want: concat(
				[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
			),
		},
		{
			name:    "QDCOUNT is zero without questions, whatever the header says",
			message: Message{Header: Header{ID: 1, QDCount: 7}},
			want:    []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "header, question and answer",
			message: Message{
				Header:    Header{ID: 1234, QR: true},
				Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
				Answers: []ResourceRecord{
					{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
				},
			},
			want: concat(
				[]byte{0x04, 0xD2, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08"),
			),
		},
		{
			name: "answers follow the questions and are encoded in order",
			message: Message{
				Header: Header{ID: 0xBEEF, QR: true},
				Questions: []Question{
					{Name: "a.io", Type: TypeA, Class: ClassIN},
					{Name: "b.io", Type: TypeA, Class: ClassIN},
				},
				Answers: []ResourceRecord{
					{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1, Data: []byte{1, 1, 1, 1}},
					{Name: "b.io", Type: TypeA, Class: ClassIN, TTL: 2, Data: []byte{2, 2, 2, 2}},
				},
			},
			want: concat(
				[]byte{0xBE, 0xEF, 0x80, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x01b\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01"),
				[]byte("\x01b\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x02\x00\x04\x02\x02\x02\x02"),
			),
		},
		{
			name: "ANCOUNT comes from the answers, not from the header",
			message: Message{
				Header: Header{ID: 1, ANCount: 9},
				Answers: []ResourceRecord{
					{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1, Data: []byte{1, 1, 1, 1}},
				},
			},
			want: concat(
				[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01"),
			),
		},
		{
			name:    "ANCOUNT is zero without answers, whatever the header says",
			message: Message{Header: Header{ID: 1, ANCount: 9}},
			want:    []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "NSCOUNT and ARCOUNT are zero, whatever the header says",
			message: Message{
				Header:    Header{ID: 1, NSCount: 3, ARCount: 4},
				Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
			},
			want: concat(
				[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.message.Encode()
			if err != nil {
				t.Fatalf("Encode() returned an error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Encode() = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestMessageEncodeDoesNotModifyTheMessage(t *testing.T) {
	message := Message{
		Header:    Header{ID: 1, QDCount: 7, ANCount: 9},
		Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1, Data: []byte{1, 1, 1, 1}}},
	}

	if _, err := message.Encode(); err != nil {
		t.Fatalf("Encode() returned an error: %v", err)
	}

	if message.Header.QDCount != 7 {
		t.Errorf("Encode() changed Header.QDCount to %d", message.Header.QDCount)
	}
	if message.Header.ANCount != 9 {
		t.Errorf("Encode() changed Header.ANCount to %d", message.Header.ANCount)
	}
}

func TestMessageEncodeRejectsInvalidQuestion(t *testing.T) {
	message := Message{
		Header:    Header{ID: 1234, QR: true},
		Questions: []Question{{Name: strings.Repeat("a", 64) + ".io", Type: TypeA, Class: ClassIN}},
	}

	if got, err := message.Encode(); err == nil {
		t.Errorf("Encode() = % x, want an error", got)
	}
}

func TestMessageEncodeRejectsTooManyQuestions(t *testing.T) {
	message := Message{Questions: make([]Question, 65536)}

	if _, err := message.Encode(); err == nil {
		t.Error("Encode() accepted 65536 questions, which QDCOUNT cannot count")
	}
}

func TestMessageEncodeRejectsInvalidAnswer(t *testing.T) {
	message := Message{
		Header:    Header{ID: 1234, QR: true},
		Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
		Answers:   []ResourceRecord{{Name: "a..io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}}},
	}

	if got, err := message.Encode(); err == nil {
		t.Errorf("Encode() = % x, want an error", got)
	}
}

func TestMessageEncodeRejectsTooManyAnswers(t *testing.T) {
	message := Message{Answers: make([]ResourceRecord, 65536)}

	if _, err := message.Encode(); err == nil {
		t.Error("Encode() accepted 65536 answers, which ANCOUNT cannot count")
	}
}

func TestMessageEncodeWithLimit(t *testing.T) {
	// The header takes 12 bytes, each question 10 and each answer 20.
	message := Message{
		Header: Header{ID: 0x0102, QR: true, RD: true},
		Questions: []Question{
			{Name: "a.io", Type: TypeA, Class: ClassIN},
			{Name: "b.io", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1, Data: []byte{1, 1, 1, 1}},
			{Name: "b.io", Type: TypeA, Class: ClassIN, TTL: 2, Data: []byte{2, 2, 2, 2}},
		},
	}

	questionA := []byte("\x01a\x02io\x00\x00\x01\x00\x01")
	questionB := []byte("\x01b\x02io\x00\x00\x01\x00\x01")
	answerA := []byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01")
	answerB := []byte("\x01b\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x02\x00\x04\x02\x02\x02\x02")

	tests := []struct {
		name  string
		limit int
		want  []byte
	}{
		{
			name:  "everything fits exactly",
			limit: 72,
			want: concat(
				[]byte{0x01, 0x02, 0x81, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB, answerA, answerB,
			),
		},
		{
			name:  "everything fits with room to spare",
			limit: 512,
			want: concat(
				[]byte{0x01, 0x02, 0x81, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB, answerA, answerB,
			),
		},
		{
			name:  "one byte short drops the last answer and sets TC",
			limit: 71,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB, answerA,
			),
		},
		{
			name:  "room for exactly one answer",
			limit: 52,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB, answerA,
			),
		},
		{
			name:  "no room for any answer",
			limit: 51,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB,
			),
		},
		{
			name:  "the questions fit exactly",
			limit: 32,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				questionA, questionB,
			),
		},
		{
			name:  "a question that does not fit is dropped along with every answer",
			limit: 31,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				questionA,
			),
		},
		{
			name:  "one question fits exactly",
			limit: 22,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				questionA,
			),
		},
		{
			name:  "one byte short of the first question",
			limit: 21,
			want:  []byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "room for the header alone",
			limit: 12,
			want:  []byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := message.EncodeWithLimit(tt.limit)
			if err != nil {
				t.Fatalf("EncodeWithLimit(%d) returned an error: %v", tt.limit, err)
			}
			if len(got) > tt.limit {
				t.Errorf("EncodeWithLimit(%d) returned %d bytes", tt.limit, len(got))
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeWithLimit(%d) = % x, want % x", tt.limit, got, tt.want)
			}
		})
	}
}

func TestMessageEncodeWithLimitDropsAnswersOnceQuestionIsDropped(t *testing.T) {
	// The second question takes 70 bytes and does not fit, but the 20-byte
	// answer would. It must be left out all the same: the answer section
	// cannot start before the question section is complete.
	message := Message{
		Header: Header{ID: 0x0102, QR: true},
		Questions: []Question{
			{Name: "a.io", Type: TypeA, Class: ClassIN},
			{Name: strings.Repeat("b", 61) + ".io", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 1, Data: []byte{1, 1, 1, 1}},
		},
	}

	got, err := message.EncodeWithLimit(60)
	if err != nil {
		t.Fatalf("EncodeWithLimit(60) returned an error: %v", err)
	}

	want := concat(
		[]byte{0x01, 0x02, 0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
	)

	if !bytes.Equal(got, want) {
		t.Errorf("EncodeWithLimit(60) = % x, want % x", got, want)
	}
}

func TestMessageEncodeWithLimitKeepsTruncationFlag(t *testing.T) {
	message := Message{Header: Header{ID: 1, TC: true}}

	got, err := message.EncodeWithLimit(512)
	if err != nil {
		t.Fatalf("EncodeWithLimit returned an error: %v", err)
	}

	want := []byte{0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	if !bytes.Equal(got, want) {
		t.Errorf("EncodeWithLimit(512) = % x, want % x", got, want)
	}
}

func TestMessageEncodeWithLimitRejectsLimitBelowHeaderSize(t *testing.T) {
	for _, limit := range []int{-1, 0, 11} {
		if got, err := (Message{}).EncodeWithLimit(limit); err == nil {
			t.Errorf("EncodeWithLimit(%d) = % x, want an error", limit, got)
		}
	}
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Message
	}{
		{
			name: "header only",
			data: []byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Message{Header: Header{ID: 1234, RD: true}},
		},
		{
			name: "query with one question",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
			),
			want: Message{
				Header:    Header{ID: 1234, RD: true, QDCount: 1},
				Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
			},
		},
		{
			name: "query with several questions",
			data: concat(
				[]byte{0xBE, 0xEF, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x01b\x02io\x00\x00\x05\x00\x01"),
				[]byte("\x00\x00\x02\x00\x01"),
			),
			want: Message{
				Header: Header{ID: 0xBEEF, QDCount: 3},
				Questions: []Question{
					{Name: "a.io", Type: TypeA, Class: ClassIN},
					{Name: "b.io", Type: 5, Class: ClassIN},
					{Name: ".", Type: 2, Class: ClassIN},
				},
			},
		},
		{
			name: "second question compressed with a pointer into the first",
			data: concat(
				[]byte{0x9D, 0x5A, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
				[]byte("\x03def\xC0\x10\x00\x01\x00\x01"), // pointer to offset 16: longassdomainname.com
			),
			want: Message{
				Header: Header{ID: 0x9D5A, RD: true, QDCount: 2},
				Questions: []Question{
					{Name: "abc.longassdomainname.com", Type: TypeA, Class: ClassIN},
					{Name: "def.longassdomainname.com", Type: TypeA, Class: ClassIN},
				},
			},
		},
		{
			name: "questions that are nothing but a pointer to the first",
			data: concat(
				[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\xC0\x0C\x00\x1C\x00\x01"),
				[]byte("\xC0\x0C\x00\x05\x00\x01"),
			),
			want: Message{
				Header: Header{ID: 1, QDCount: 3},
				Questions: []Question{
					{Name: "a.io", Type: TypeA, Class: ClassIN},
					{Name: "a.io", Type: 28, Class: ClassIN},
					{Name: "a.io", Type: 5, Class: ClassIN},
				},
			},
		},
		{
			name: "response with an answer",
			data: concat(
				[]byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x4c\x4c\x15\x15"),
			),
			want: Message{
				Header:    Header{ID: 1234, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 1},
				Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
				Answers: []ResourceRecord{
					{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 3600, Data: []byte{76, 76, 21, 21}},
				},
			},
		},
		{
			name: "response with compressed answers",
			data: concat(
				[]byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
				[]byte("\xC0\x0C\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x4c\x4c\x15\x15"),
				[]byte("\xC0\x0C\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x4c\x4c\x15\x16"),
			),
			want: Message{
				Header:    Header{ID: 1234, QR: true, RD: true, RA: true, QDCount: 1, ANCount: 2},
				Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
				Answers: []ResourceRecord{
					{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 3600, Data: []byte{76, 76, 21, 21}},
					{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 3600, Data: []byte{76, 76, 21, 22}},
				},
			},
		},
		{
			name: "answers without a question",
			data: concat(
				[]byte{0x00, 0x07, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"),
			),
			want: Message{
				Header:  Header{ID: 7, QR: true, ANCount: 1},
				Answers: []ResourceRecord{{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{1, 2, 3, 4}}},
			},
		},
		{
			name: "records of the authority and additional sections are not decoded",
			data: concat(
				[]byte{0x00, 0x07, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"),
				[]byte("\xC0\x0E\x00\x02\x00\x01\x00\x00\x00\x3c\x00\x05\x02ns\xC0\x0E"),
				[]byte("\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"),
			),
			want: Message{
				Header:    Header{ID: 7, QR: true, QDCount: 1, ANCount: 1, NSCount: 1, ARCount: 1},
				Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
				Answers:   []ResourceRecord{{Name: "a.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{1, 2, 3, 4}}},
			},
		},
		{
			name: "bytes after the last question are ignored",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // EDNS OPT record
			),
			want: Message{
				Header:    Header{ID: 1234, RD: true, QDCount: 1, ARCount: 1},
				Questions: []Question{{Name: "a.io", Type: TypeA, Class: ClassIN}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMessage(tt.data)
			if err != nil {
				t.Fatalf("parseMessage returned an error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMessage() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseMessageRejectsInvalidMessages(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "no data", data: nil},
		{name: "one byte short of a header", data: make([]byte, headerSize-1)},
		{
			name: "QDCOUNT promises a question that is not there",
			data: []byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "QDCOUNT promises more questions than there are",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
			),
		},
		{
			name: "question cut short",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00"),
			),
		},
		{
			name: "question with a pointer to itself",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\xC0\x0C\x00\x01\x00\x01"),
			),
		},
		{
			name: "question with a pointer past the end of the message",
			data: concat(
				[]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\xC0\x40\x00\x01\x00\x01"),
			),
		},
		{
			name: "ANCOUNT promises an answer that is not there",
			data: concat(
				[]byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
			),
		},
		{
			name: "ANCOUNT promises more answers than there are",
			data: concat(
				[]byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"),
			),
		},
		{
			name: "answer cut short",
			data: concat(
				[]byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
				[]byte("\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03"),
			),
		},
		{
			name: "largest possible ANCOUNT with no answers",
			data: []byte{0x04, 0xD2, 0x81, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "largest possible QDCOUNT with no questions",
			data: []byte{0x04, 0xD2, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := parseMessage(tt.data); err == nil {
				t.Errorf("parseMessage() = %+v, want an error", got)
			}
		})
	}
}

// Whatever parseMessage accepts must survive a trip through the encoder and
// back, and no input may make it panic.
func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x02\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\xC0\x0C\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\xFF\xFF\x00\x00\x00\x00\x00\x00\x3f"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00" +
		"\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xC0\x10\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xC0\x0C\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\xC0\x12\x00\x01\x00\x01\xC0\x0C\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" +
		"\x03www\x07example\x03com\x00\x00\x01\x00\x01" +
		"\xC0\x0C\x00\x05\x00\x01\x00\x00\x01\x2C\x00\x06\x03web\xC0\x10" +
		"\xC0\x2D\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x5D\xB8\xD8\x22"))
	f.Add([]byte("\x04\xD2\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
		"\x07example\x03com\x00\x00\x06\x00\x01" +
		"\xC0\x0C\x00\x06\x00\x01\x00\x00\x0E\x10\x00\x27\x02ns\xC0\x0C\x0afirst.last\xC0\x0C" +
		"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"))
	f.Add([]byte("\x04\xD2\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
		"\x07example\x03com\x00\x00\x0F\x00\x01" +
		"\xC0\x0C\x00\x0F\x00\x01\x00\x00\x0E\x10\x00\x09\x00\x0A\x04mail\xC0\x0C"))

	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := parseMessage(data)
		if err != nil {
			return
		}

		if len(message.Questions) != int(message.Header.QDCount) {
			t.Fatalf("parsed %d questions, but QDCOUNT is %d", len(message.Questions), message.Header.QDCount)
		}
		if len(message.Answers) != int(message.Header.ANCount) {
			t.Fatalf("parsed %d answers, but ANCOUNT is %d", len(message.Answers), message.Header.ANCount)
		}

		encoded, err := message.Encode()
		if err != nil {
			t.Fatalf("parsed message %+v does not encode: %v", message, err)
		}

		again, err := parseMessage(encoded)
		if err != nil {
			t.Fatalf("encoding % x of parsed message %+v does not parse: %v", encoded, message, err)
		}
		if !reflect.DeepEqual(again.Questions, message.Questions) {
			t.Fatalf("questions changed in a round trip: %+v became %+v", message.Questions, again.Questions)
		}
		if !reflect.DeepEqual(again.Answers, message.Answers) {
			t.Fatalf("answers changed in a round trip: %+v became %+v", message.Answers, again.Answers)
		}
	})
}

// Whatever appendName accepts must decode to a name that encodes the same way.
func FuzzAppendName(f *testing.F) {
	f.Add("")
	f.Add(".")
	f.Add("codecrafters.io")
	f.Add("codecrafters.io.")
	f.Add(`first\.last.example.com`)
	f.Add(`a\\b.com`)
	f.Add(`\065\000\255.com`)
	f.Add(`a\.`)
	f.Add(`a\\.`)
	f.Add(`\`)
	f.Add("a..b")
	f.Add(strings.Repeat("a", 63) + "." + strings.Repeat("b", 64))

	f.Fuzz(func(t *testing.T, name string) {
		encoded, err := appendName(nil, name)
		if err != nil {
			return
		}

		if len(encoded) > maxNameLength {
			t.Fatalf("%q encodes to %d bytes, more than the limit of %d", name, len(encoded), maxNameLength)
		}

		decoded, next, err := parseName(encoded, 0)
		if err != nil {
			t.Fatalf("encoding % x of %q does not decode: %v", encoded, name, err)
		}
		if next != len(encoded) {
			t.Fatalf("decoding the encoding of %q stops at offset %d of %d", name, next, len(encoded))
		}

		again, err := appendName(nil, decoded)
		if err != nil {
			t.Fatalf("%q decoded as %q, which does not encode: %v", name, decoded, err)
		}
		if !bytes.Equal(again, encoded) {
			t.Fatalf("%q encodes to % x but decodes as %q, which encodes to % x", name, encoded, decoded, again)
		}
	})
}

// concat joins byte slices into a new slice.
func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
