package main

import (
	"bytes"
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

func TestServerRespondsToEveryPacket(t *testing.T) {
	client := dialTestServer(t, startTestServer(t))

	// More than one packet, to prove the server keeps serving after a reply.
	for i, payload := range []string{"first", "second", "third"} {
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatalf("packet %d: failed to send: %v", i, err)
		}

		if _, err := client.Read(make([]byte, 512)); err != nil {
			t.Fatalf("packet %d: no response received: %v", i, err)
		}
	}
}

func TestServerRespondsToMultipleClients(t *testing.T) {
	addr := startTestServer(t)

	first := dialTestServer(t, addr)
	second := dialTestServer(t, addr)

	for name, client := range map[string]*net.UDPConn{"first": first, "second": second} {
		if _, err := client.Write([]byte(name)); err != nil {
			t.Fatalf("%s client: failed to send: %v", name, err)
		}
	}

	// Each client must get its own reply, addressed to its own source port.
	for name, client := range map[string]*net.UDPConn{"first": first, "second": second} {
		if _, err := client.Read(make([]byte, 512)); err != nil {
			t.Fatalf("%s client: no response received: %v", name, err)
		}
	}
}

// exchange sends query to the server behind client and returns the reply.
func exchange(t *testing.T, client *net.UDPConn, query []byte) []byte {
	t.Helper()

	if _, err := client.Write(query); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no response received: %v", err)
	}

	return buf[:n]
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

func TestServerRepliesWithHeaderQuestionAndAnswerSections(t *testing.T) {
	client := dialTestServer(t, startTestServer(t))

	got := exchange(t, client, codecraftersQuery)

	want := []byte{
		0x04, 0xD2, // ID: 1234
		0x80, 0x00, // flags: QR set, everything else zero
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
