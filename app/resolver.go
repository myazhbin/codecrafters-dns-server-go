package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// A resolver finds the answer to a single question.
type resolver interface {
	// resolve returns the answer to question. recursionDesired is the RD flag
	// of the query that the question came in. It gives up with an error when
	// ctx is done.
	resolve(ctx context.Context, question Question, recursionDesired bool) (resolution, error)
}

// A resolution is the answer that a resolver found to a question.
type resolution struct {
	Answers   []ResourceRecord // Records that answer the question, possibly none.
	RCode     uint8            // Response code to report, such as RCodeNoError.
	Truncated bool             // Whether records are missing because they did not fit.
}

// newResolver returns the resolver that forwards questions to the DNS server
// at address, which has the form <ip>:<port>. Without an address, it returns a
// resolver that makes answers up instead.
func newResolver(address string) (resolver, error) {
	if address == "" {
		return staticResolver{}, nil
	}

	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("invalid resolver address %q: %w", address, err)
	}

	// An address such as "127.0.0.1:" resolves, to port 0, which no server
	// can be reached on.
	if addr.Port == 0 {
		return nil, fmt.Errorf("invalid resolver address %q: no port to send queries to", address)
	}

	return &forwardingResolver{addr: addr}, nil
}

// staticResolver answers without looking anything up: every domain name has
// the same A record and no records of any other type or class.
type staticResolver struct{}

func (staticResolver) resolve(_ context.Context, question Question, _ bool) (resolution, error) {
	if question.Type != TypeA || question.Class != ClassIN {
		return resolution{RCode: RCodeNoError}, nil
	}

	return resolution{
		Answers: []ResourceRecord{
			{Name: question.Name, Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
		},
		RCode: RCodeNoError,
	}, nil
}

// maxUpstreamSize is the size in bytes of the largest reply read from an
// upstream DNS server. A reply should not exceed maxUDPSize, since queries are
// sent without the extension that allows more, but there is no harm in reading
// one from a server that does not stick to that.
const maxUpstreamSize = 4096

// forwardingResolver resolves questions by asking another DNS server.
type forwardingResolver struct {
	addr *net.UDPAddr // The DNS server that questions are forwarded to.
}

// resolve sends question to the upstream DNS server, in a query of its own,
// and returns what the server answers.
func (f *forwardingResolver) resolve(ctx context.Context, question Question, recursionDesired bool) (resolution, error) {
	// There is no point in asking once nobody waits for the answer any more.
	if err := ctx.Err(); err != nil {
		return resolution{}, err
	}

	query := Message{
		Header:    Header{ID: randomID(), RD: recursionDesired},
		Questions: []Question{question},
	}

	packet, err := query.Encode()
	if err != nil {
		return resolution{}, err
	}

	// A socket of its own for every query, connected to the server: the
	// operating system picks a port that is hard to guess and drops whatever
	// does not come from the server, both of which make replies hard to forge.
	conn, err := net.DialUDP("udp", nil, f.addr)
	if err != nil {
		return resolution{}, err
	}
	defer conn.Close()

	// Reading from the socket has no notion of ctx, so make the read fail as
	// soon as ctx is done.
	stop := context.AfterFunc(ctx, func() { conn.SetReadDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write(packet); err != nil {
		return resolution{}, err
	}

	buf := make([]byte, maxUpstreamSize)

	for {
		size, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return resolution{}, fmt.Errorf("no reply from %s: %w", f.addr, ctx.Err())
			}
			return resolution{}, err
		}

		reply, err := parseMessage(buf[:size])
		if err != nil {
			fmt.Printf("Ignoring packet from %s: %v\n", f.addr, err)
			continue
		}

		// Anything else than the reply to this query is skipped rather than
		// treated as a failure: the real reply may still be on its way.
		if err := checkReply(reply, query); err != nil {
			fmt.Printf("Ignoring packet from %s: %v\n", f.addr, err)
			continue
		}

		return resolution{
			Answers:   reply.Answers,
			RCode:     reply.Header.RCode,
			Truncated: reply.Header.TC,
		}, nil
	}
}

// checkReply returns an error unless reply is a reply to query: a response
// with the same ID that repeats the one question that was asked.
func checkReply(reply, query Message) error {
	if !reply.Header.QR {
		return errors.New("it is a query, not a response")
	}
	if reply.Header.ID != query.Header.ID {
		return fmt.Errorf("it has ID %d, the query has ID %d", reply.Header.ID, query.Header.ID)
	}
	if len(reply.Questions) != 1 || reply.Questions[0] != query.Questions[0] {
		return fmt.Errorf("it is about %+v, the query is about %+v", reply.Questions, query.Questions)
	}

	return nil
}

// randomID returns an ID for a query that cannot be predicted, so that a reply
// to the query cannot be forged by guessing what its ID has to be.
func randomID() uint16 {
	var id [2]byte

	// Read fills id entirely and never returns an error.
	rand.Read(id[:])

	return binary.BigEndian.Uint16(id[:])
}
