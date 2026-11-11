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
		{name: "compression pointer", data: []byte("\x01a\x00\xC0\x00"), offset: 3},
		{name: "label containing a dot", data: []byte("\x03a.b\x03com\x00")},
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
			name:  "a question that does not fit is dropped along with every answer",
			limit: 31,
			want: concat(
				[]byte{0x01, 0x02, 0x83, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				questionA,
			),
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

	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := parseMessage(data)
		if err != nil {
			return
		}

		if len(message.Questions) != int(message.Header.QDCount) {
			t.Fatalf("parsed %d questions, but QDCOUNT is %d", len(message.Questions), message.Header.QDCount)
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
	})
}

// concat joins byte slices into a new slice.
func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
