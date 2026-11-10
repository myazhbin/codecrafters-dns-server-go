package main

import (
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
