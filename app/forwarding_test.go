package main

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// These tests run the server in front of a fake upstream DNS server and talk
// to it over UDP, like the tester of the last stage of the challenge does.

// startForwardingServer runs a server that forwards its queries to upstream
// and gives up on a query after timeout. It returns a client connected to it.
func startForwardingServer(t *testing.T, upstream *fakeUpstream, timeout time.Duration) *net.UDPConn {
	t.Helper()

	addr := startTestServerWith(t, &server{
		resolver: &forwardingResolver{addr: upstream.addr},
		timeout:  timeout,
	})

	return dialTestServer(t, addr)
}

// waitFor fails the test unless condition becomes true within two seconds.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestForwardingServerAnswersWithRecordsOfUpstream(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, map[string][]byte{
		"codecrafters.io": {76, 76, 21, 21},
	}))
	client := startForwardingServer(t, upstream, 2*time.Second)

	got := exchange(t, client, codecraftersQuery)

	// The answer is the one of the upstream, TTL and address included,
	// rather than anything the server made up.
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
		0x00, 0x00, 0x01, 0x2C, // TTL: 300
		0x00, 0x04, // RDLENGTH: 4
		0x4C, 0x4C, 0x15, 0x15, // RDATA: 76.76.21.21
	}

	if !bytes.Equal(got, want) {
		t.Errorf("response = % x, want % x", got, want)
	}
}

func TestForwardingServerSplitsQuestionsAndMergesAnswers(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, map[string][]byte{
		"abc.longassdomainname.com": {127, 0, 0, 1},
		"def.longassdomainname.com": {127, 0, 0, 2},
	}))
	client := startForwardingServer(t, upstream, 2*time.Second)

	// Two questions in one query, the second of which is compressed. The
	// upstream ignores queries that ask more than one question.
	query := concat(
		[]byte{0x9D, 0x5A, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03def\xC0\x10\x00\x01\x00\x01"), // pointer to offset 16: longassdomainname.com
	)

	got := exchange(t, client, query)

	want := concat(
		[]byte{0x9D, 0x5A, 0x81, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03def\x11longassdomainname\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2C\x00\x04\x7F\x00\x00\x01"),
		[]byte("\x03def\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2C\x00\x04\x7F\x00\x00\x02"),
	)

	if !bytes.Equal(got, want) {
		t.Errorf("response = % x, want % x", got, want)
	}

	// The upstream was asked the questions one by one, in order.
	queries := upstream.received()
	if len(queries) != 2 {
		t.Fatalf("upstream received %d queries, want 2: %+v", len(queries), queries)
	}

	for i, name := range []string{"abc.longassdomainname.com", "def.longassdomainname.com"} {
		wantQuestions := []Question{{Name: name, Type: TypeA, Class: ClassIN}}

		if !reflect.DeepEqual(queries[i].Questions, wantQuestions) {
			t.Errorf("query %d to upstream asks %+v, want %+v", i+1, queries[i].Questions, wantQuestions)
		}
		if queries[i].Header.QR || queries[i].Header.Opcode != OpcodeQuery {
			t.Errorf("query %d to upstream has header %+v, want a standard query", i+1, queries[i].Header)
		}
	}
}

func TestForwardingServerMergesAnswersOfManyQuestions(t *testing.T) {
	addresses := map[string][]byte{
		"one.example":   {10, 0, 0, 1},
		"two.example":   {10, 0, 0, 2},
		"three.example": {10, 0, 0, 3},
		"four.example":  {10, 0, 0, 4},
	}
	names := []string{"three.example", "one.example", "four.example", "two.example", "one.example"}

	upstream := startFakeUpstream(t, addressBook(t, addresses))
	client := startForwardingServer(t, upstream, 2*time.Second)

	query := Message{Header: Header{ID: 77}}
	want := Message{Header: Header{ID: 77, QR: true, QDCount: 5, ANCount: 5}}

	for _, name := range names {
		question := Question{Name: name, Type: TypeA, Class: ClassIN}

		query.Questions = append(query.Questions, question)
		want.Questions = append(want.Questions, question)
		want.Answers = append(want.Answers, ResourceRecord{
			Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: addresses[name],
		})
	}

	got := mustParse(t, exchange(t, client, mustEncode(t, query)))

	// The answers come in the order of the questions they belong to.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("response = %+v, want %+v", got, want)
	}
	if queries := upstream.received(); len(queries) != len(names) {
		t.Errorf("upstream received %d queries, want %d", len(queries), len(names))
	}
}

func TestForwardingServerKeepsItsOwnHeader(t *testing.T) {
	// The upstream sets flags that the reply of the server must not have.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		reply := replyTo(query, ResourceRecord{
			Name: query.Questions[0].Name, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4},
		})
		reply.Header.AA = true
		reply.Header.RA = true
		reply.Header.Z = 7

		return packets(t, reply)
	})
	client := startForwardingServer(t, upstream, 2*time.Second)

	for _, recursionDesired := range []bool{false, true} {
		query := queryWithHeader(t, Header{ID: 0xBEEF, RD: recursionDesired})
		got := mustParseHeader(t, exchange(t, client, query))

		want := Header{ID: 0xBEEF, QR: true, RD: recursionDesired, QDCount: 1, ANCount: 1}

		if got != want {
			t.Errorf("RD %t: response header = %+v, want %+v", recursionDesired, got, want)
		}
	}

	queries := upstream.received()
	if len(queries) != 2 {
		t.Fatalf("upstream received %d queries, want 2", len(queries))
	}

	// The upstream is asked to recurse only if the client asked for it.
	if queries[0].Header.RD || !queries[1].Header.RD {
		t.Errorf("upstream received queries with RD %t and %t, want false and true",
			queries[0].Header.RD, queries[1].Header.RD)
	}

	// The ID of the query is not the one sent on to the upstream, where it
	// could be guessed by whoever sent the query.
	for _, query := range queries {
		if query.Header.ID == 0xBEEF {
			t.Errorf("upstream received a query with the ID of the client: %+v", query.Header)
		}
	}
}

func TestForwardingServerDoesNotForwardWhatItCannotAnswer(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		wantRCode uint8
	}{
		{
			name:      "query with an unsupported opcode",
			packet:    queryWithHeader(t, Header{ID: 1, Opcode: 2}),
			wantRCode: RCodeNotImplemented,
		},
		{
			name:      "query that is cut short",
			packet:    codecraftersQuery[:len(codecraftersQuery)-1],
			wantRCode: RCodeFormatError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := startFakeUpstream(t, addressBook(t, nil))
			client := startForwardingServer(t, upstream, 2*time.Second)

			if got := mustParseHeader(t, exchange(t, client, tt.packet)).RCode; got != tt.wantRCode {
				t.Errorf("response RCODE = %d, want %d", got, tt.wantRCode)
			}

			// A query that is forwarded shows that the upstream is reachable
			// and, as the upstream sees packets in the order they were sent,
			// that nothing was forwarded before it.
			exchange(t, client, queryWithHeader(t, Header{ID: 2}))

			if queries := upstream.received(); len(queries) != 1 {
				t.Errorf("upstream received %d queries, want only the one sent afterwards: %+v", len(queries), queries)
			}
		})
	}
}

func TestForwardingServerReportsFailureWhenUpstreamDoesNotReply(t *testing.T) {
	upstream := startFakeUpstream(t, func(Message) [][]byte { return nil })
	client := startForwardingServer(t, upstream, 100*time.Millisecond)

	started := time.Now()
	got := mustParse(t, exchange(t, client, codecraftersQuery))
	elapsed := time.Since(started)

	want := Message{
		Header:    Header{ID: 1234, QR: true, RD: true, RCode: RCodeServerFailure, QDCount: 1},
		Questions: []Question{{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("response = %+v, want %+v", got, want)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("server gave up on the upstream after %v, before its timeout of 100ms", elapsed)
	}
}

func TestForwardingServerLeavesOutAnswersWhenAQuestionFails(t *testing.T) {
	// The upstream answers the first question but not the second.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		if query.Questions[0].Name != "answered.example" {
			return nil
		}

		return packets(t, replyTo(query, ResourceRecord{
			Name: "answered.example", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4},
		}))
	})
	client := startForwardingServer(t, upstream, 100*time.Millisecond)

	questions := []Question{
		{Name: "answered.example", Type: TypeA, Class: ClassIN},
		{Name: "ignored.example", Type: TypeA, Class: ClassIN},
	}

	got := mustParse(t, exchange(t, client, mustEncode(t, Message{Header: Header{ID: 9}, Questions: questions})))

	want := Message{
		Header:    Header{ID: 9, QR: true, RCode: RCodeServerFailure, QDCount: 2},
		Questions: questions,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("response = %+v, want %+v", got, want)
	}
}

func TestForwardingServerPassesOnResponseCodeOfUpstream(t *testing.T) {
	const rcodeNameError, rcodeRefused = 3, 5

	// One name exists, the others get the response code that is in their name.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		switch query.Questions[0].Name {
		case "exists.example":
			return packets(t, replyTo(query, ResourceRecord{
				Name: "exists.example", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4},
			}))
		case "refused.example":
			reply := replyTo(query)
			reply.Header.RCode = rcodeRefused
			return packets(t, reply)
		default:
			reply := replyTo(query)
			reply.Header.RCode = rcodeNameError
			return packets(t, reply)
		}
	})
	client := startForwardingServer(t, upstream, 2*time.Second)

	answer := ResourceRecord{Name: "exists.example", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4}}

	tests := []struct {
		name        string
		names       []string
		wantRCode   uint8
		wantAnswers []ResourceRecord
	}{
		{name: "name that does not exist", names: []string{"missing.example"}, wantRCode: rcodeNameError},
		{name: "name that exists", names: []string{"exists.example"}, wantRCode: RCodeNoError, wantAnswers: []ResourceRecord{answer}},
		{
			name:        "the answers that there are come with the error",
			names:       []string{"exists.example", "missing.example"},
			wantRCode:   rcodeNameError,
			wantAnswers: []ResourceRecord{answer},
		},
		{
			name:        "an error is not undone by a later question that goes well",
			names:       []string{"missing.example", "exists.example"},
			wantRCode:   rcodeNameError,
			wantAnswers: []ResourceRecord{answer},
		},
		{
			name:      "the first error is the one that is reported",
			names:     []string{"refused.example", "missing.example"},
			wantRCode: rcodeRefused,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := Message{Header: Header{ID: 5}}
			for _, name := range tt.names {
				query.Questions = append(query.Questions, Question{Name: name, Type: TypeA, Class: ClassIN})
			}

			got := mustParse(t, exchange(t, client, mustEncode(t, query)))

			if got.Header.RCode != tt.wantRCode {
				t.Errorf("response RCODE = %d, want %d", got.Header.RCode, tt.wantRCode)
			}
			if !reflect.DeepEqual(got.Answers, tt.wantAnswers) {
				t.Errorf("response answers = %+v, want %+v", got.Answers, tt.wantAnswers)
			}
			if !reflect.DeepEqual(got.Questions, query.Questions) {
				t.Errorf("response questions = %+v, want %+v", got.Questions, query.Questions)
			}
		})
	}
}

func TestForwardingServerPassesOnTruncationOfUpstream(t *testing.T) {
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		reply := replyTo(query)
		reply.Header.TC = query.Questions[0].Name == "big.example"

		return packets(t, reply)
	})
	client := startForwardingServer(t, upstream, 2*time.Second)

	tests := []struct {
		name          string
		names         []string
		wantTruncated bool
	}{
		{name: "complete answer", names: []string{"small.example"}, wantTruncated: false},
		{name: "truncated answer", names: []string{"big.example"}, wantTruncated: true},
		{name: "truncated answer among complete ones", names: []string{"small.example", "big.example", "small.example"}, wantTruncated: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := Message{Header: Header{ID: 5}}
			for _, name := range tt.names {
				query.Questions = append(query.Questions, Question{Name: name, Type: TypeA, Class: ClassIN})
			}

			if got := mustParseHeader(t, exchange(t, client, mustEncode(t, query))).TC; got != tt.wantTruncated {
				t.Errorf("response TC = %t, want %t", got, tt.wantTruncated)
			}
		})
	}
}

func TestForwardingServerRelaysCompressedReplyWithoutPointers(t *testing.T) {
	// A CNAME and the address of its target, with every repeated name
	// replaced by a pointer. See TestForwardingResolverExpandsCompressedReply
	// for the layout.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		return [][]byte{concat(
			[]byte{byte(query.Header.ID >> 8), byte(query.Header.ID)},
			[]byte{0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			[]byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
			[]byte("\xC0\x0C\x00\x05\x00\x01\x00\x00\x01\x2C\x00\x06\x03web\xC0\x10"),
			[]byte("\xC0\x2D\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x5D\xB8\xD8\x22"),
		)}
	})
	client := startForwardingServer(t, upstream, 2*time.Second)

	query := mustEncode(t, Message{
		Header:    Header{ID: 0x0A0B, RD: true},
		Questions: []Question{{Name: "www.example.com", Type: TypeA, Class: ClassIN}},
	})

	got := exchange(t, client, query)

	// The names are at other offsets in this reply than in the one of the
	// upstream, so a pointer that was copied over would lead somewhere else.
	want := concat(
		[]byte{0x0A, 0x0B, 0x81, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		[]byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
		[]byte("\x03www\x07example\x03com\x00\x00\x05\x00\x01\x00\x00\x01\x2C\x00\x11\x03web\x07example\x03com\x00"),
		[]byte("\x03web\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x5D\xB8\xD8\x22"),
	)

	if !bytes.Equal(got, want) {
		t.Errorf("response = % x, want % x", got, want)
	}
}

func TestForwardingServerTruncatesMergedAnswersThatDoNotFit(t *testing.T) {
	// Twenty addresses per name: 12 + 21 + 20*16 = 353 bytes for one
	// question, which fits, but not for two.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		var answers []ResourceRecord
		for i := 0; i < 20; i++ {
			answers = append(answers, ResourceRecord{
				Name: query.Questions[0].Name, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{10, 0, 0, byte(i)},
			})
		}

		return packets(t, replyTo(query, answers...))
	})
	client := startForwardingServer(t, upstream, 2*time.Second)

	query := mustEncode(t, Message{
		Header: Header{ID: 3},
		Questions: []Question{
			{Name: "a.io", Type: TypeA, Class: ClassIN},
			{Name: "b.io", Type: TypeA, Class: ClassIN},
		},
	})

	response := exchange(t, client, query)

	if len(response) > maxUDPSize {
		t.Fatalf("response is %d bytes, more than the %d that fit in a UDP packet", len(response), maxUDPSize)
	}

	got := mustParse(t, response)

	// 12 bytes of header and two 10-byte questions leave room for 24 of the
	// 40 answers, at 20 bytes each.
	if !got.Header.TC {
		t.Error("response does not have the TC flag set")
	}
	if len(got.Questions) != 2 || len(got.Answers) != 24 {
		t.Errorf("response has %d questions and %d answers, want 2 and 24", len(got.Questions), len(got.Answers))
	}
}

func TestForwardingServerHandlesQueriesAtTheSameTime(t *testing.T) {
	// The upstream never answers questions about slow.example.
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		if query.Questions[0].Name == "slow.example" {
			return nil
		}

		return packets(t, replyTo(query, ResourceRecord{
			Name: query.Questions[0].Name, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4},
		}))
	})

	// The server waits much longer for the upstream than the clients of this
	// test wait for the server: a query that is held up by the one before it
	// goes unanswered as far as they can tell.
	addr := startTestServerWith(t, &server{
		resolver: &forwardingResolver{addr: upstream.addr},
		timeout:  time.Minute,
	})

	slow := dialTestServer(t, addr)
	if _, err := slow.Write(mustEncode(t, Message{
		Header:    Header{ID: 1},
		Questions: []Question{{Name: "slow.example", Type: TypeA, Class: ClassIN}},
	})); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	waitFor(t, "the slow query to reach the upstream", func() bool { return len(upstream.received()) == 1 })

	fast := dialTestServer(t, addr)
	got := mustParse(t, exchange(t, fast, mustEncode(t, Message{
		Header:    Header{ID: 2},
		Questions: []Question{{Name: "fast.example", Type: TypeA, Class: ClassIN}},
	})))

	if got.Header.ID != 2 || len(got.Answers) != 1 {
		t.Errorf("response = %+v, want the answer to query 2", got)
	}
}

func TestForwardingServerStopsWithoutWaitingForUpstream(t *testing.T) {
	upstream := startFakeUpstream(t, func(Message) [][]byte { return nil })

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := &server{resolver: &forwardingResolver{addr: upstream.addr}, timeout: time.Minute}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serve(conn)
	}()

	client := dialTestServer(t, conn.LocalAddr().(*net.UDPAddr))
	if _, err := client.Write(codecraftersQuery); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	waitFor(t, "the query to reach the upstream", func() bool { return len(upstream.received()) == 1 })

	// The query is now waiting for a reply that will not come for a minute.
	conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return while a query was waiting for the upstream")
	}
}
