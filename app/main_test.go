package main

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

// startTestServer runs serve on an ephemeral loopback port, so tests never
// collide with a real server on port 2053, and returns the address it listens on.
func startTestServer(t *testing.T) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(conn)
	}()

	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return conn.LocalAddr().(*net.UDPAddr)
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(conn)
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

func TestRespondToHeaderWithoutQuestion(t *testing.T) {
	// A header on its own is enough to reply to: nothing after it is read yet.
	response, err := respond(Header{ID: 42, RD: true}.appendTo(nil))
	if err != nil {
		t.Fatalf("respond returned an error: %v", err)
	}

	got := mustParseHeader(t, response)
	want := Header{ID: 42, QR: true, RD: true, QDCount: 1, ANCount: 1}

	if got != want {
		t.Errorf("response header = %+v, want %+v", got, want)
	}
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
