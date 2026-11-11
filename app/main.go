package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// resolveTimeout is how long the server spends on resolving the questions of
// a query before it gives up and reports a failure.
const resolveTimeout = 5 * time.Second

// maxInFlight is how many queries the server works on at the same time. It
// keeps a flood of queries from using up memory and sockets. Packets that
// arrive while that many queries are in progress wait their turn.
const maxInFlight = 100

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	resolverAddress := flag.String("resolver", "",
		"address of the DNS server to forward queries to, in the form <ip>:<port>")
	flag.Parse()

	resolver, err := newResolver(*resolverAddress)
	if err != nil {
		fmt.Println("Failed to set up resolver:", err)
		os.Exit(1)
	}
	if *resolverAddress != "" {
		fmt.Println("Forwarding queries to", *resolverAddress)
	}

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

	server := &server{resolver: resolver, timeout: resolveTimeout}
	server.serve(udpConn)
}

// server answers DNS queries with what its resolver finds.
type server struct {
	resolver resolver      // Where the answers to questions come from.
	timeout  time.Duration // How long resolving the questions of one query may take.
}

// serve answers the DNS queries received on udpConn. It returns once reading
// from the connection fails, which is what happens when the connection is
// closed, and the queries still in progress at that point have been dealt with.
//
// Each query is handled on its own, so that one whose answer is slow to come
// does not hold up the others.
func (s *server) serve(udpConn *net.UDPConn) {
	// Stop resolving on the way out and wait for the handlers to notice.
	var handlers sync.WaitGroup
	defer handlers.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slots := make(chan struct{}, maxInFlight)
	buf := make([]byte, maxUDPSize)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			return
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		// buf is overwritten by the next packet while this one is handled.
		packet := bytes.Clone(buf[:size])

		slots <- struct{}{}
		handlers.Go(func() {
			defer func() { <-slots }()
			s.handle(ctx, udpConn, packet, source)
		})
	}
}

// handle replies to a packet that was received on udpConn from source.
func (s *server) handle(ctx context.Context, udpConn *net.UDPConn, packet []byte, source *net.UDPAddr) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	response, err := s.respond(ctx, packet)
	if err != nil {
		fmt.Printf("Not replying to %s: %v\n", source, err)
		return
	}

	if _, err := udpConn.WriteToUDP(response, source); err != nil {
		fmt.Println("Failed to send response:", err)
	}
}

// respond returns the wire format of the reply to a packet. It returns an
// error, and no reply, for a packet that should not be answered at all: one
// too short to hold a header, which leaves no ID to reply with, or one that is
// itself a response, since answering responses lets two servers bounce packets
// off each other forever.
func (s *server) respond(ctx context.Context, packet []byte) ([]byte, error) {
	header, err := parseHeader(packet)
	if err != nil {
		return nil, err
	}
	if header.QR {
		return nil, errors.New("packet is a response, not a query")
	}

	// A reply must fit in a single UDP packet. One that does not is cut short
	// and flagged as truncated.
	return s.buildResponse(ctx, header, packet).EncodeWithLimit(maxUDPSize)
}

// buildResponse returns the reply to the query in packet, whose header has
// already been decoded. The ID, OPCODE and RD flag of the query are copied
// into the reply.
//
// Only standard queries are supported: any other kind gets a "not implemented"
// reply that consists of a header alone, and so does a standard query that
// cannot be decoded, with a "format error". Otherwise the reply repeats the
// questions of the query and answers them. Domain names that were compressed
// in the query are written out in full in the reply.
func (s *server) buildResponse(ctx context.Context, header Header, packet []byte) Message {
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

	// The questions are resolved one at a time, as a resolver may well ignore
	// a query that asks several at once, and what comes back is gathered into
	// a single reply.
	for _, question := range query.Questions {
		result, err := s.resolver.resolve(ctx, question, header.RD)
		if err != nil {
			fmt.Printf("Failed to resolve %q: %v\n", question.Name, err)

			// Answers to some of the questions would pass for a complete
			// reply, so there are none at all in a failure.
			response.Header.RCode = RCodeServerFailure
			response.Header.TC = false
			response.Answers = nil

			return response
		}

		response.Answers = append(response.Answers, result.Answers...)
		response.Header.TC = response.Header.TC || result.Truncated

		// A reply has room for one response code. The first question that
		// did not go well decides what it is.
		if response.Header.RCode == RCodeNoError {
			response.Header.RCode = result.RCode
		}
	}

	return response
}
