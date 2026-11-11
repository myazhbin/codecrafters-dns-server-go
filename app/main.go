package main

import (
	"errors"
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

// serve answers the DNS queries received on udpConn. It returns once reading
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
			fmt.Printf("Not replying to %s: %v\n", source, err)
			continue
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

// respond returns the wire format of the reply to a packet. It returns an
// error, and no reply, for a packet that should not be answered at all: one
// too short to hold a header, which leaves no ID to reply with, or one that is
// itself a response, since answering responses lets two servers bounce packets
// off each other forever.
func respond(packet []byte) ([]byte, error) {
	query, err := parseHeader(packet)
	if err != nil {
		return nil, err
	}
	if query.QR {
		return nil, errors.New("packet is a response, not a query")
	}

	return buildResponse(query).Encode()
}

// buildResponse returns the reply to a query with the given header. The ID,
// OPCODE and RD flag of the query are copied into the reply.
//
// Only standard queries are supported, and what they ask is not inspected yet:
// each one is answered with a question about the A record of codecrafters.io
// and that record. Any other kind of query gets a "not implemented" reply that
// consists of a header alone.
func buildResponse(query Header) Message {
	response := Message{
		Header: Header{
			ID:     query.ID,
			QR:     true,
			Opcode: query.Opcode,
			RD:     query.RD,
			RCode:  RCodeNoError,
		},
	}

	if query.Opcode != OpcodeQuery {
		response.Header.RCode = RCodeNotImplemented
		return response
	}

	response.Questions = []Question{
		{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
	}
	response.Answers = []ResourceRecord{
		{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
	}

	return response
}
