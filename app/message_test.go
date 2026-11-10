package main

import (
	"bytes"
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

// concat joins byte slices into a new slice.
func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
