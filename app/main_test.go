package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// startTestServer runs a server that makes its answers up, without an upstream
// resolver, and returns the address it listens on.
func startTestServer(t *testing.T) *net.UDPAddr {
	t.Helper()

	return startTestServerWith(t, &server{resolver: staticResolver{}, timeout: 2 * time.Second})
}

// startTestServerWith runs s on an ephemeral loopback port, so tests never
// collide with a real server on port 2053, and returns the address it listens on.
func startTestServerWith(t *testing.T, s *server) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serve(conn)
	}()

	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return conn.LocalAddr().(*net.UDPAddr)
}

// respond returns the reply to packet of a server that makes its answers up,
// without an upstream resolver.
func respond(packet []byte) ([]byte, error) {
	s := &server{resolver: staticResolver{}, timeout: 2 * time.Second}

	return s.respond(context.Background(), packet)
}

// dialTestServer returns a UDP client connected to addr whose reads and writes
// fail after a short deadline instead of hanging the test run.
func dialTestServer(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()

	client, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("failed to dial %s: %v", addr, err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}

	return client
}

// exchange sends packet to the server behind client and returns the reply.
func exchange(t *testing.T, client *net.UDPConn, packet []byte) []byte {
	t.Helper()

	if _, err := client.Write(packet); err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no response received: %v", err)
	}

	return buf[:n]
}

// mustEncode returns the wire format of message.
func mustEncode(t *testing.T, message Message) []byte {
	t.Helper()

	packet, err := message.Encode()
	if err != nil {
		t.Fatalf("failed to encode %+v: %v", message, err)
	}

	return packet
}

// mustParse returns the DNS message in packet.
func mustParse(t *testing.T, packet []byte) Message {
	t.Helper()

	message, err := parseMessage(packet)
	if err != nil {
		t.Fatalf("failed to parse % x: %v", packet, err)
	}

	return message
}

// mustParseHeader returns the header of the DNS message in packet.
func mustParseHeader(t *testing.T, packet []byte) Header {
	t.Helper()

	header, err := parseHeader(packet)
	if err != nil {
		t.Fatalf("failed to parse the header of % x: %v", packet, err)
	}

	return header
}

// queryWithHeader returns the wire format of a query for the A record of
// codecrafters.io that carries the given header.
func queryWithHeader(t *testing.T, header Header) []byte {
	t.Helper()

	return mustEncode(t, Message{
		Header:    header,
		Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
	})
}

// codecraftersQuery is a query for the A record of codecrafters.io with ID
// 1234 and the RD flag set, as sent by `dig +noedns codecrafters.io`.
var codecraftersQuery = []byte{
	0x04, 0xD2, // ID: 1234
	0x01, 0x00, // flags: RD
	0x00, 0x01, // QDCOUNT: 1
	0x00, 0x00, // ANCOUNT: 0
	0x00, 0x00, // NSCOUNT: 0
	0x00, 0x00, // ARCOUNT: 0
	0x0C, 'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's',
	0x02, 'i', 'o',
	0x00,       // end of name
	0x00, 0x01, // QTYPE: A
	0x00, 0x01, // QCLASS: IN
}

func TestServerRepliesToEveryQuery(t *testing.T) {
	client := dialTestServer(t, startTestServer(t))

	// More than one query, to prove the server keeps serving after a reply.
	for _, id := range []uint16{1, 2, 3} {
		response := exchange(t, client, queryWithHeader(t, Header{ID: id}))

		if got := mustParseHeader(t, response).ID; got != id {
			t.Errorf("reply to query %d has ID %d", id, got)
		}
	}
}

func TestServerRepliesToMultipleClients(t *testing.T) {
	addr := startTestServer(t)

	clients := map[uint16]*net.UDPConn{
		100: dialTestServer(t, addr),
		200: dialTestServer(t, addr),
	}

	for id, client := range clients {
		if _, err := client.Write(queryWithHeader(t, Header{ID: id})); err != nil {
			t.Fatalf("client %d: failed to send query: %v", id, err)
		}
	}

	// Each client must get the reply to its own query, sent to its own port.
	for id, client := range clients {
		buf := make([]byte, 512)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("client %d: no response received: %v", id, err)
		}

		if got := mustParseHeader(t, buf[:n]).ID; got != id {
			t.Errorf("client %d received the reply to query %d", id, got)
		}
	}
}

func TestServerKeepsQueriesThatArriveTogetherApart(t *testing.T) {
	addr := startTestServer(t)

	const clients, queriesPerClient = 8, 50

	// Every client fires off its queries as fast as it can, so that the
	// server is always busy with several of them at once.
	failures := make(chan string, clients*queriesPerClient)
	done := make(chan struct{})

	for c := 0; c < clients; c++ {
		client := dialTestServer(t, addr)

		go func() {
			defer func() { done <- struct{}{} }()

			for q := 0; q < queriesPerClient; q++ {
				id := uint16(c*1000 + q)
				question := Question{Name: fmt.Sprintf("query-%d.client-%d.example", q, c), Type: TypeA, Class: ClassIN}

				query, err := Message{Header: Header{ID: id}, Questions: []Question{question}}.Encode()
				if err != nil {
					failures <- fmt.Sprintf("client %d: failed to encode query %d: %v", c, q, err)
					return
				}
				if _, err := client.Write(query); err != nil {
					failures <- fmt.Sprintf("client %d: failed to send query %d: %v", c, q, err)
					return
				}

				buf := make([]byte, 512)
				n, err := client.Read(buf)
				if err != nil {
					failures <- fmt.Sprintf("client %d: no response to query %d: %v", c, q, err)
					return
				}

				response, err := parseMessage(buf[:n])
				if err != nil {
					failures <- fmt.Sprintf("client %d: response to query %d does not parse: %v", c, q, err)
					return
				}

				// A reply that belongs to another query, or that is made up
				// of pieces of two, has the wrong ID or the wrong name in it.
				wantAnswer := ResourceRecord{Name: question.Name, Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}}
				if response.Header.ID != id ||
					!reflect.DeepEqual(response.Questions, []Question{question}) ||
					!reflect.DeepEqual(response.Answers, []ResourceRecord{wantAnswer}) {
					failures <- fmt.Sprintf("client %d: response to query %d about %q is %+v", c, q, question.Name, response)
				}
			}
		}()
	}

	for c := 0; c < clients; c++ {
		<-done
	}
	close(failures)

	for failure := range failures {
		t.Error(failure)
	}
}

func TestServerRepliesWithHeaderQuestionAndAnswerSections(t *testing.T) {
	client := dialTestServer(t, startTestServer(t))

	got := exchange(t, client, codecraftersQuery)

	want := []byte{
		0x04, 0xD2, // ID: 1234, as in the query
		0x81, 0x00, // flags: QR set, RD set as in the query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0

		// Question section.
		0x0C, 'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's',
		0x02, 'i', 'o',
		0x00,       // end of name
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN

		// Answer section.
		0x0C, 'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's',
		0x02, 'i', 'o',
		0x00,       // end of name
		0x00, 0x01, // TYPE: A
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0x3C, // TTL: 60
		0x00, 0x04, // RDLENGTH: 4
		0x08, 0x08, 0x08, 0x08, // RDATA: 8.8.8.8
	}

	if !bytes.Equal(got, want) {
		t.Errorf("response = % x, want % x", got, want)
	}
}

func TestServerMimicsHeaderOfQuery(t *testing.T) {
	client := dialTestServer(t, startTestServer(t))

	query := queryWithHeader(t, Header{ID: 0xBEEF, Opcode: 2, RD: true})
	got := mustParseHeader(t, exchange(t, client, query))

	want := Header{ID: 0xBEEF, QR: true, Opcode: 2, RD: true, RCode: RCodeNotImplemented}

	if got != want {
		t.Errorf("response header = %+v, want %+v", got, want)
	}
}

func TestServerIgnoresPacketsItCannotAnswer(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty packet", packet: []byte{}},
		{name: "one byte short of a header", packet: codecraftersQuery[:headerSize-1]},
		{name: "a response rather than a query", packet: queryWithHeader(t, Header{ID: 1, QR: true})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := dialTestServer(t, startTestServer(t))

			if _, err := client.Write(tt.packet); err != nil {
				t.Fatalf("failed to send packet: %v", err)
			}

			// The server handles packets in the order they arrive, so had it
			// replied to the packet above, that reply would be read here
			// instead of the reply to this query.
			response := exchange(t, client, queryWithHeader(t, Header{ID: 0x7777}))

			if got := mustParseHeader(t, response).ID; got != 0x7777 {
				t.Errorf("first reply has ID %#04x, want the reply to query 0x7777", got)
			}
		})
	}
}

func TestServeReturnsWhenConnectionIsClosed(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := &server{resolver: staticResolver{}, timeout: 2 * time.Second}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serve(conn)
	}()

	conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after the connection was closed")
	}
}

func TestRespondMimicsID(t *testing.T) {
	for _, id := range []uint16{0, 1, 1234, 0x00FF, 0xFF00, 0xABCD, 0xFFFF} {
		t.Run(fmt.Sprintf("ID %d", id), func(t *testing.T) {
			response, err := respond(queryWithHeader(t, Header{ID: id}))
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}

			if got := mustParseHeader(t, response).ID; got != id {
				t.Errorf("response ID = %d, want %d", got, id)
			}
		})
	}
}

func TestRespondMimicsOpcodeAndSetsResponseCode(t *testing.T) {
	for opcode := uint8(0); opcode <= 15; opcode++ {
		t.Run(fmt.Sprintf("OPCODE %d", opcode), func(t *testing.T) {
			response, err := respond(queryWithHeader(t, Header{ID: 1, Opcode: opcode}))
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}

			header := mustParseHeader(t, response)

			if header.Opcode != opcode {
				t.Errorf("response OPCODE = %d, want %d", header.Opcode, opcode)
			}

			// Only standard queries (OPCODE 0) are implemented.
			wantRCode := RCodeNotImplemented
			if opcode == OpcodeQuery {
				wantRCode = RCodeNoError
			}
			if header.RCode != wantRCode {
				t.Errorf("response RCODE = %d, want %d", header.RCode, wantRCode)
			}
		})
	}
}

func TestRespondMimicsRecursionDesired(t *testing.T) {
	for _, rd := range []bool{false, true} {
		t.Run(fmt.Sprintf("RD %t", rd), func(t *testing.T) {
			response, err := respond(queryWithHeader(t, Header{ID: 1, RD: rd}))
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}

			if got := mustParseHeader(t, response).RD; got != rd {
				t.Errorf("response RD = %t, want %t", got, rd)
			}
		})
	}
}

func TestRespondDoesNotMimicOtherFlags(t *testing.T) {
	// A query has no business setting these, and they must not leak into the reply.
	query := queryWithHeader(t, Header{ID: 1, AA: true, TC: true, RA: true, Z: 7, RCode: 15})

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	got := mustParseHeader(t, response)
	want := Header{ID: 1, QR: true, QDCount: 1, ANCount: 1}

	if got != want {
		t.Errorf("response header = %+v, want %+v", got, want)
	}
}

func TestRespondToStandardQuery(t *testing.T) {
	response, err := respond(queryWithHeader(t, Header{ID: 0xCAFE, RD: true}))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	want := mustEncode(t, Message{
		Header:    Header{ID: 0xCAFE, QR: true, RD: true},
		Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondToUnsupportedOpcodeIsHeaderOnly(t *testing.T) {
	response, err := respond(queryWithHeader(t, Header{ID: 0xCAFE, Opcode: 1, RD: true}))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	// The counts must be zero as well: nothing follows the header.
	want := mustEncode(t, Message{
		Header: Header{ID: 0xCAFE, QR: true, Opcode: 1, RD: true, RCode: RCodeNotImplemented},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondToQueryWithoutQuestions(t *testing.T) {
	response, err := respond(Header{ID: 42, RD: true}.appendTo(nil))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	// Nothing was asked, so there is nothing to repeat and nothing to answer.
	want := mustEncode(t, Message{Header: Header{ID: 42, QR: true, RD: true}})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondMimicsQuestionAndAnswersIt(t *testing.T) {
	names := []string{
		"codecrafters.io",
		"google.com",
		"abc.longassdomainname.com",
		"CodeCrafters.IO",
		"localhost",
		"a.b.c.d.e.f.example.org",
		".",
	}

	// The tester asks about random domains, so do the same.
	random := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		names = append(names, randomDomain(random))
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			query := mustEncode(t, Message{
				Header:    Header{ID: 0x1A2B, RD: true},
				Questions: []Question{{Name: name, Type: TypeA, Class: ClassIN}},
			})

			response, err := respond(query)
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}

			want := mustEncode(t, Message{
				Header:    Header{ID: 0x1A2B, QR: true, RD: true},
				Questions: []Question{{Name: name, Type: TypeA, Class: ClassIN}},
				Answers:   []ResourceRecord{{Name: name, Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}}},
			})

			if !bytes.Equal(response, want) {
				t.Errorf("response = % x, want % x", response, want)
			}
		})
	}
}

// randomDomain returns a domain name made of two to four random labels.
func randomDomain(random *rand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789-"

	labels := make([]string, 2+random.Intn(3))
	for i := range labels {
		label := make([]byte, 1+random.Intn(20))
		for j := range label {
			label[j] = letters[random.Intn(len(letters))]
		}
		labels[i] = string(label)
	}

	return strings.Join(labels, ".")
}

func TestRespondAnswersEveryQuestion(t *testing.T) {
	query := mustEncode(t, Message{
		Header: Header{ID: 7},
		Questions: []Question{
			{Name: "abc.example.com", Type: TypeA, Class: ClassIN},
			{Name: "def.example.com", Type: TypeA, Class: ClassIN},
			{Name: "example.org", Type: TypeA, Class: ClassIN},
		},
	})

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	want := mustEncode(t, Message{
		Header: Header{ID: 7, QR: true},
		Questions: []Question{
			{Name: "abc.example.com", Type: TypeA, Class: ClassIN},
			{Name: "def.example.com", Type: TypeA, Class: ClassIN},
			{Name: "example.org", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "abc.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			{Name: "def.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
			{Name: "example.org", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondToCompressedQuery(t *testing.T) {
	// Two questions, the second of which reuses the end of the first one's name.
	query := concat(
		[]byte{0x9D, 0x5A, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03def\xC0\x10\x00\x01\x00\x01"), // pointer to offset 16: longassdomainname.com
	)

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	// Every name in the reply is written out in full.
	want := concat(
		[]byte{0x9D, 0x5A, 0x81, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03def\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08"),
		[]byte("\x03def\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08"),
	)

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondToQueryWithFullyCompressedQuestion(t *testing.T) {
	// The second question is nothing but a pointer to the name of the first.
	query := concat(
		[]byte{0x00, 0x2A, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
		[]byte("\xC0\x0C\x00\x01\x00\x01"),
	)

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}
	answer := ResourceRecord{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}}

	want := mustEncode(t, Message{
		Header:    Header{ID: 42, QR: true},
		Questions: []Question{question, question},
		Answers:   []ResourceRecord{answer, answer},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondTruncatesReplyToCompressedQueryThatExpandsPastUDPLimit(t *testing.T) {
	// One long name followed by 40 questions that are just a pointer to it:
	// 286 bytes of query that would expand to several kilobytes of reply.
	name := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + ".example.com"

	query := mustEncode(t, Message{
		Header:    Header{ID: 5, QDCount: 41},
		Questions: []Question{{Name: name, Type: TypeA, Class: ClassIN}},
	})
	query[5] = 41 // QDCOUNT, which Encode set to the single question above
	for i := 0; i < 40; i++ {
		query = append(query, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
	}

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	if len(response) > maxUDPSize {
		t.Fatalf("response is %d bytes, more than the %d that fit in a UDP packet", len(response), maxUDPSize)
	}

	got := mustParse(t, response)

	if !got.Header.TC {
		t.Error("response does not have the TC flag set")
	}
	if got.Header.ID != 5 || !got.Header.QR {
		t.Errorf("response header = %+v, want ID 5 and QR set", got.Header)
	}
	for i, question := range got.Questions {
		if want := (Question{Name: name, Type: TypeA, Class: ClassIN}); question != want {
			t.Errorf("question %d = %+v, want %+v", i, question, want)
		}
	}
	// Each question takes 79 bytes written out in full: 6 fit in 500 bytes.
	if len(got.Questions) != 6 {
		t.Errorf("response has %d questions, want 6", len(got.Questions))
	}
}

func TestRespondWithFormatErrorToInvalidCompression(t *testing.T) {
	header := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	tests := []struct {
		name  string
		query []byte
	}{
		{name: "pointer to itself", query: concat(header, []byte("\xC0\x0C\x00\x01\x00\x01"))},
		{name: "pointer to its own labels", query: concat(header, []byte("\x01a\xC0\x0C\x00\x01\x00\x01"))},
		{name: "pointer forwards", query: concat(header, []byte("\xC0\x12\x00\x01\x00\x01\x01a\x00"))},
		{name: "pointer past the end of the query", query: concat(header, []byte("\x01a\xC1\xFF\x00\x01\x00\x01"))},
		{name: "pointer cut short", query: concat(header, []byte("\x01a\xC0"))},
	}

	want := mustEncode(t, Message{
		Header: Header{ID: 0xABCD, QR: true, RD: true, RCode: RCodeFormatError},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := respond(tt.query)
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}
			if !bytes.Equal(response, want) {
				t.Errorf("response = % x, want % x", response, want)
			}
		})
	}
}

func TestRespondOnlyAnswersQuestionsAboutARecords(t *testing.T) {
	const (
		typeAAAA  = 28
		classCHAO = 3
	)

	questions := []Question{
		{Name: "a.example.com", Type: typeAAAA, Class: ClassIN},
		{Name: "b.example.com", Type: TypeA, Class: ClassIN},
		{Name: "c.example.com", Type: TypeA, Class: classCHAO},
	}

	response, err := respond(mustEncode(t, Message{Header: Header{ID: 7}, Questions: questions}))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	// Every question is repeated as it was asked, but the server only has A
	// records in the IN class to answer with.
	want := mustEncode(t, Message{
		Header:    Header{ID: 7, QR: true},
		Questions: questions,
		Answers: []ResourceRecord{
			{Name: "b.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondIgnoresWhatFollowsTheQuestions(t *testing.T) {
	// dig appends an EDNS OPT record to its queries unless told not to.
	query := concat(
		[]byte{0x04, 0xD2, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[]byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"),
		[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	)

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	want := mustEncode(t, Message{
		Header:    Header{ID: 1234, QR: true, RD: true},
		Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondWithFormatErrorToMalformedQuery(t *testing.T) {
	header := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	tests := []struct {
		name  string
		query []byte
	}{
		{name: "QDCOUNT promises a question that is not there", query: header},
		{name: "name cut short", query: concat(header, []byte("\x0ccodecraf"))},
		{name: "name without terminator", query: concat(header, []byte("\x0ccodecrafters\x02io"))},
		{name: "type and class cut short", query: concat(header, []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00"))},
		{name: "reserved label type", query: concat(header, []byte("\x80codecrafters\x02io\x00\x00\x01\x00\x01"))},
	}

	// The header could be read, so the reply still mimics it. Nothing else is known.
	want := mustEncode(t, Message{
		Header: Header{ID: 0xABCD, QR: true, RD: true, RCode: RCodeFormatError},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := respond(tt.query)
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}
			if !bytes.Equal(response, want) {
				t.Errorf("response = % x, want % x", response, want)
			}
		})
	}
}

func TestRespondDoesNotParseQueriesWithUnsupportedOpcode(t *testing.T) {
	// What follows the header of such a query may not even be a question
	// section, so "not implemented" wins over "format error".
	query := concat(
		[]byte{0xAB, 0xCD, 0x28, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x0ccodecraf"),
	)

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	want := mustEncode(t, Message{
		Header: Header{ID: 0xABCD, QR: true, Opcode: 5, RCode: RCodeNotImplemented},
	})

	if !bytes.Equal(response, want) {
		t.Errorf("response = % x, want % x", response, want)
	}
}

func TestRespondTruncatesReplyThatDoesNotFitInUDPPacket(t *testing.T) {
	// 20 questions about a 27-byte name take 12 + 20*31 = 632 bytes on their
	// own, before a single answer is added.
	questions := make([]Question, 20)
	for i := range questions {
		questions[i] = Question{Name: fmt.Sprintf("host-%02d.subdomain.example", i), Type: TypeA, Class: ClassIN}
	}

	query := mustEncode(t, Message{Header: Header{ID: 99, RD: true}, Questions: questions})

	response, err := respond(query)
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	if len(response) > maxUDPSize {
		t.Fatalf("response is %d bytes, more than the %d that fit in a UDP packet", len(response), maxUDPSize)
	}

	got := mustParse(t, response)

	// (512 - 12) / 31 = 16 questions fit, and then no answers.
	want := Message{
		Header:    Header{ID: 99, QR: true, TC: true, RD: true, QDCount: 16},
		Questions: questions[:16],
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("response = %+v, want %+v", got, want)
	}
	if wantSize := headerSize + 16*31; len(response) != wantSize {
		t.Errorf("response is %d bytes, want %d: something follows the questions", len(response), wantSize)
	}
}

func TestRespondDoesNotTruncateReplyThatFits(t *testing.T) {
	// 8 questions about a 24-byte name: 12 + 8*30 + 8*40 = 572 bytes would
	// not fit, but 7 of them take 12 + 7*30 + 7*40 = 502 bytes and do.
	questions := make([]Question, 7)
	for i := range questions {
		questions[i] = Question{Name: fmt.Sprintf("host-%d.subdomain.example", i), Type: TypeA, Class: ClassIN}
	}

	response, err := respond(mustEncode(t, Message{Header: Header{ID: 99}, Questions: questions}))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	header := mustParseHeader(t, response)
	want := Header{ID: 99, QR: true, QDCount: 7, ANCount: 7}

	if header != want {
		t.Errorf("response header = %+v, want %+v", header, want)
	}
	if len(response) != 502 {
		t.Errorf("response is %d bytes, want 502", len(response))
	}
}

// A reply, if there is one, must be a well-formed DNS message that fits in a
// UDP packet and carries the ID of the query, whatever the query looks like.
func FuzzRespond(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x09\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01a\x02io\x00\x00\x01\x00\x01\x00\x00\x1c\x00\x01"))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\xC0\x0C\x00\x01\x00\x01"))
	f.Add(append([]byte{0x04, 0xD2, 0x01, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{0x00, 0x00, 0x01, 0x00, 0x01}, 100)...))
	f.Add([]byte("\x04\xD2\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00" +
		"\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xC0\x10\x00\x01\x00\x01"))
	f.Add(append([]byte("\x04\xD2\x01\x00\x00\x29\x00\x00\x00\x00\x00\x00"+
		"\x3faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x03com\x00\x00\x01\x00\x01"),
		bytes.Repeat([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01}, 40)...))

	f.Fuzz(func(t *testing.T, packet []byte) {
		response, err := respond(packet)
		if err != nil {
			if response != nil {
				t.Fatalf("respond returned both a reply and an error: %v", err)
			}
			return
		}

		if len(response) > maxUDPSize {
			t.Fatalf("reply is %d bytes, more than the %d that fit in a UDP packet", len(response), maxUDPSize)
		}

		query, err := parseHeader(packet)
		if err != nil {
			t.Fatalf("respond replied to a packet without a header: % x", packet)
		}

		reply, err := parseMessage(response)
		if err != nil {
			t.Fatalf("reply % x does not parse: %v", response, err)
		}

		if !reply.Header.QR {
			t.Fatal("reply does not have the QR flag set")
		}
		if reply.Header.ID != query.ID {
			t.Fatalf("reply has ID %d, query has ID %d", reply.Header.ID, query.ID)
		}
		if reply.Header.Opcode != query.Opcode {
			t.Fatalf("reply has OPCODE %d, query has OPCODE %d", reply.Header.Opcode, query.Opcode)
		}
		if reply.Header.RD != query.RD {
			t.Fatalf("reply has RD %t, query has RD %t", reply.Header.RD, query.RD)
		}
	})
}

func TestRespondRejectsPacketsItCannotAnswer(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "nil packet", packet: nil},
		{name: "empty packet", packet: []byte{}},
		{name: "a single byte", packet: []byte{0x04}},
		{name: "one byte short of a header", packet: codecraftersQuery[:headerSize-1]},
		{name: "a response rather than a query", packet: queryWithHeader(t, Header{ID: 1, QR: true})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if response, err := respond(tt.packet); err == nil {
				t.Errorf("respond returned % x, want an error", response)
			}
		})
	}
}

// stubResolver is a resolver that answers from a table, for tests of what the
// server does with the outcome of resolving each question.
type stubResolver struct {
	// outcomes holds what resolve returns for a question, by name. A name
	// that is not in it resolves to no answers and no error.
	outcomes map[string]stubOutcome

	// calls records every call to resolve, in order.
	calls []stubCall
}

type stubOutcome struct {
	resolution resolution
	err        error
}

type stubCall struct {
	question         Question
	recursionDesired bool
}

func (r *stubResolver) resolve(_ context.Context, question Question, recursionDesired bool) (resolution, error) {
	r.calls = append(r.calls, stubCall{question, recursionDesired})

	outcome := r.outcomes[question.Name]

	return outcome.resolution, outcome.err
}

func TestRespondPutsOutcomesOfQuestionsTogether(t *testing.T) {
	const rcodeNameError, rcodeRefused = 3, 5

	address := func(name string, last byte) ResourceRecord {
		return ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{10, 0, 0, last}}
	}

	outcomes := map[string]stubOutcome{
		"one.example":       {resolution: resolution{Answers: []ResourceRecord{address("one.example", 1)}}},
		"two.example":       {resolution: resolution{Answers: []ResourceRecord{address("two.example", 2), address("two.example", 3)}}},
		"none.example":      {resolution: resolution{}},
		"missing.example":   {resolution: resolution{RCode: rcodeNameError}},
		"refused.example":   {resolution: resolution{RCode: rcodeRefused}},
		"truncated.example": {resolution: resolution{Answers: []ResourceRecord{address("truncated.example", 4)}, Truncated: true}},
		"broken.example":    {err: errors.New("no reply")},
	}

	tests := []struct {
		name          string
		names         []string
		wantRCode     uint8
		wantTruncated bool
		wantAnswers   []ResourceRecord
		wantResolved  []string // The questions that the resolver was asked.
	}{
		{
			name:         "one question",
			names:        []string{"one.example"},
			wantAnswers:  []ResourceRecord{address("one.example", 1)},
			wantResolved: []string{"one.example"},
		},
		{
			name:         "answers follow the order of the questions",
			names:        []string{"two.example", "one.example"},
			wantAnswers:  []ResourceRecord{address("two.example", 2), address("two.example", 3), address("one.example", 1)},
			wantResolved: []string{"two.example", "one.example"},
		},
		{
			name:         "a question without answers leaves the others alone",
			names:        []string{"one.example", "none.example", "two.example"},
			wantAnswers:  []ResourceRecord{address("one.example", 1), address("two.example", 2), address("two.example", 3)},
			wantResolved: []string{"one.example", "none.example", "two.example"},
		},
		{
			name:         "the same question twice is resolved twice",
			names:        []string{"one.example", "one.example"},
			wantAnswers:  []ResourceRecord{address("one.example", 1), address("one.example", 1)},
			wantResolved: []string{"one.example", "one.example"},
		},
		{
			name:         "response code of the only question",
			names:        []string{"missing.example"},
			wantRCode:    rcodeNameError,
			wantResolved: []string{"missing.example"},
		},
		{
			name:         "a response code does not stop the questions after it",
			names:        []string{"missing.example", "one.example"},
			wantRCode:    rcodeNameError,
			wantAnswers:  []ResourceRecord{address("one.example", 1)},
			wantResolved: []string{"missing.example", "one.example"},
		},
		{
			name:         "a response code is kept when an earlier question went well",
			names:        []string{"one.example", "missing.example"},
			wantRCode:    rcodeNameError,
			wantAnswers:  []ResourceRecord{address("one.example", 1)},
			wantResolved: []string{"one.example", "missing.example"},
		},
		{
			name:         "the first of two response codes wins",
			names:        []string{"refused.example", "missing.example"},
			wantRCode:    rcodeRefused,
			wantResolved: []string{"refused.example", "missing.example"},
		},
		{
			name:         "the first of two response codes wins, the other way around",
			names:        []string{"missing.example", "refused.example"},
			wantRCode:    rcodeNameError,
			wantResolved: []string{"missing.example", "refused.example"},
		},
		{
			name:          "truncation of the only question",
			names:         []string{"truncated.example"},
			wantTruncated: true,
			wantAnswers:   []ResourceRecord{address("truncated.example", 4)},
			wantResolved:  []string{"truncated.example"},
		},
		{
			name:          "truncation is kept when a later question is complete",
			names:         []string{"truncated.example", "one.example"},
			wantTruncated: true,
			wantAnswers:   []ResourceRecord{address("truncated.example", 4), address("one.example", 1)},
			wantResolved:  []string{"truncated.example", "one.example"},
		},
		{
			name:          "truncation of a later question",
			names:         []string{"one.example", "truncated.example"},
			wantTruncated: true,
			wantAnswers:   []ResourceRecord{address("one.example", 1), address("truncated.example", 4)},
			wantResolved:  []string{"one.example", "truncated.example"},
		},
		{
			name:         "failure of the only question",
			names:        []string{"broken.example"},
			wantRCode:    RCodeServerFailure,
			wantResolved: []string{"broken.example"},
		},
		{
			name:         "a failure throws away the answers so far",
			names:        []string{"one.example", "broken.example"},
			wantRCode:    RCodeServerFailure,
			wantResolved: []string{"one.example", "broken.example"},
		},
		{
			name:         "a failure stops the questions after it",
			names:        []string{"broken.example", "one.example"},
			wantRCode:    RCodeServerFailure,
			wantResolved: []string{"broken.example"},
		},
		{
			name:         "a failure wins over a response code and a truncation before it",
			names:        []string{"missing.example", "truncated.example", "broken.example", "two.example"},
			wantRCode:    RCodeServerFailure,
			wantResolved: []string{"missing.example", "truncated.example", "broken.example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &stubResolver{outcomes: outcomes}
			s := &server{resolver: resolver, timeout: 2 * time.Second}

			query := Message{Header: Header{ID: 21}}
			for _, name := range tt.names {
				query.Questions = append(query.Questions, Question{Name: name, Type: TypeA, Class: ClassIN})
			}

			response, err := s.respond(context.Background(), mustEncode(t, query))
			if err != nil {
				t.Fatalf("respond returned an error: %v", err)
			}

			got := mustParse(t, response)

			want := Message{
				Header: Header{
					ID: 21, QR: true, TC: tt.wantTruncated, RCode: tt.wantRCode,
					QDCount: uint16(len(query.Questions)), ANCount: uint16(len(tt.wantAnswers)),
				},
				Questions: query.Questions,
				Answers:   tt.wantAnswers,
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("response = %+v, want %+v", got, want)
			}

			var resolved []string
			for _, call := range resolver.calls {
				resolved = append(resolved, call.question.Name)
			}
			if !reflect.DeepEqual(resolved, tt.wantResolved) {
				t.Errorf("resolver was asked about %v, want %v", resolved, tt.wantResolved)
			}
		})
	}
}

func TestRespondPassesQuestionAndRecursionDesiredToResolver(t *testing.T) {
	const typeMX = 15

	for _, recursionDesired := range []bool{false, true} {
		resolver := &stubResolver{}
		s := &server{resolver: resolver, timeout: 2 * time.Second}

		questions := []Question{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
			{Name: "example.com", Type: typeMX, Class: 3},
		}

		query := mustEncode(t, Message{Header: Header{ID: 1, RD: recursionDesired}, Questions: questions})

		if _, err := s.respond(context.Background(), query); err != nil {
			t.Fatalf("RD %t: respond returned an error: %v", recursionDesired, err)
		}

		want := []stubCall{
			{question: questions[0], recursionDesired: recursionDesired},
			{question: questions[1], recursionDesired: recursionDesired},
		}

		if !reflect.DeepEqual(resolver.calls, want) {
			t.Errorf("RD %t: resolver was called with %+v, want %+v", recursionDesired, resolver.calls, want)
		}
	}
}

func TestRespondDoesNotResolveWhatItCannotAnswer(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "query with an unsupported opcode", packet: queryWithHeader(t, Header{ID: 1, Opcode: 2})},
		{name: "query that is cut short", packet: codecraftersQuery[:len(codecraftersQuery)-1]},
		{name: "query whose second question is cut short", packet: concat(
			[]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			[]byte("\x01a\x02io\x00\x00\x01\x00\x01"),
			[]byte("\x01b\x02io\x00\x00\x01"),
		)},
		{name: "response", packet: queryWithHeader(t, Header{ID: 1, QR: true})},
		{name: "packet without a header", packet: codecraftersQuery[:headerSize-1]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &stubResolver{}
			s := &server{resolver: resolver, timeout: 2 * time.Second}

			// Whether there is a reply or not is checked elsewhere.
			s.respond(context.Background(), tt.packet)

			if len(resolver.calls) != 0 {
				t.Errorf("resolver was asked about %+v, want nothing", resolver.calls)
			}
		})
	}
}

func TestRespondGivesResolverContextThatEndsWithTheQuery(t *testing.T) {
	// A resolver that reports whether it was called with a live context.
	var sawLiveContext, sawDeadline bool

	s := &server{timeout: 2 * time.Second, resolver: resolverFunc(
		func(ctx context.Context, question Question, recursionDesired bool) (resolution, error) {
			sawLiveContext = ctx.Err() == nil
			_, sawDeadline = ctx.Deadline()

			return resolution{}, nil
		},
	)}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer conn.Close()

	client := dialTestServer(t, conn.LocalAddr().(*net.UDPAddr))

	s.handle(context.Background(), conn, codecraftersQuery, client.LocalAddr().(*net.UDPAddr))

	if !sawLiveContext {
		t.Error("resolver was called with a context that had already ended")
	}
	if !sawDeadline {
		t.Error("resolver was called with a context without a deadline")
	}

	// handle sent the reply to the client before it returned.
	if _, err := client.Read(make([]byte, 512)); err != nil {
		t.Errorf("no response received: %v", err)
	}
}

// resolverFunc lets a function stand in for a resolver.
type resolverFunc func(ctx context.Context, question Question, recursionDesired bool) (resolution, error)

func (f resolverFunc) resolve(ctx context.Context, question Question, recursionDesired bool) (resolution, error) {
	return f(ctx, question, recursionDesired)
}
