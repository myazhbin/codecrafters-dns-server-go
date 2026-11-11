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
	header, err := parseHeader(packet)
	if err != nil {
		return nil, err
	}
	if header.QR {
		return nil, errors.New("packet is a response, not a query")
	}

	// A reply must fit in a single UDP packet. One that does not is cut short
	// and flagged as truncated.
	return buildResponse(header, packet).EncodeWithLimit(maxUDPSize)
}

// buildResponse returns the reply to the query in packet, whose header has
// already been decoded. The ID, OPCODE and RD flag of the query are copied
// into the reply.
//
// Only standard queries are supported: any other kind gets a "not implemented"
// reply that consists of a header alone, and so does a standard query that
// cannot be decoded, with a "format error". Otherwise the reply repeats the
// questions of the query and answers them.
func buildResponse(header Header, packet []byte) Message {
	response := Message{
		Header: Header{
			ID:     header.ID,
			QR:     true,
			Opcode: header.Opcode,
			RD:     header.RD,
			RCode:  RCodeNoError,
		},
	}

	if header.Opcode != OpcodeQuery {
		response.Header.RCode = RCodeNotImplemented
		return response
	}

	query, err := parseMessage(packet)
	if err != nil {
		fmt.Println("Failed to parse query:", err)
		response.Header.RCode = RCodeFormatError
		return response
	}

	response.Questions = query.Questions
	for _, question := range query.Questions {
		response.Answers = append(response.Answers, resolve(question)...)
	}

	return response
}

// resolve returns the records that answer a question. There is no real data
// behind this server: every domain name has the same A record and no records
// of any other type or class.
func resolve(question Question) []ResourceRecord {
	if question.Type != TypeA || question.Class != ClassIN {
		return nil
	}

	return []ResourceRecord{
		{Name: question.Name, Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
	}
}
