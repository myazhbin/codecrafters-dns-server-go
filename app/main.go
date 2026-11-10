package main

import (
	"fmt"
	"net"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	serve(udpConn)
}

// serve replies to every datagram received on udpConn. It returns once reading
// from the connection fails, which is what happens when the connection is closed.
func serve(udpConn *net.UDPConn) {
	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		response, err := respond(buf[:size])
		if err != nil {
			fmt.Println("Failed to build response:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

// respond returns the wire format of the reply to a query packet. The query
// is not inspected yet: every reply is the same message, a header followed by
// a question about the A record of codecrafters.io and that record as the
// answer.
func respond(query []byte) ([]byte, error) {
	response := Message{
		Header: Header{
			ID: 1234,
			QR: true,
		},
		Questions: []Question{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
	}

	return response.Encode()
}
