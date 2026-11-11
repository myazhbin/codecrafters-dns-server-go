package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeUpstream is a DNS server under the control of a test. It stands in for
// the DNS server that queries are forwarded to.
type fakeUpstream struct {
	addr *net.UDPAddr

	mu      sync.Mutex
	queries []Message
}

// startFakeUpstream runs a DNS server on an ephemeral loopback port. Every
// packet that it receives is decoded and handed to handle, and the packets
// that handle returns are sent back in order. A query for which handle returns
// nothing is left unanswered.
func startFakeUpstream(t *testing.T, handle func(query Message) [][]byte) *fakeUpstream {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	upstream := &fakeUpstream{addr: conn.LocalAddr().(*net.UDPAddr)}

	done := make(chan struct{})
	go func() {
		defer close(done)

		buf := make([]byte, 4096)
		for {
			size, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			query, err := parseMessage(buf[:size])
			if err != nil {
				t.Errorf("upstream received a packet that does not parse: % x: %v", buf[:size], err)
				continue
			}

			upstream.mu.Lock()
			upstream.queries = append(upstream.queries, query)
			upstream.mu.Unlock()

			for _, reply := range handle(query) {
				if _, err := conn.WriteToUDP(reply, source); err != nil {
					t.Errorf("upstream failed to send a reply: %v", err)
				}
			}
		}
	}()

	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return upstream
}

// received returns the queries that the upstream has received so far, in the
// order in which they arrived.
func (u *fakeUpstream) received() []Message {
	u.mu.Lock()
	defer u.mu.Unlock()

	return append([]Message(nil), u.queries...)
}

// replyTo returns a response to query that carries the given answers, the way
// a recursive resolver would send it.
func replyTo(query Message, answers ...ResourceRecord) Message {
	return Message{
		Header:    Header{ID: query.Header.ID, QR: true, RD: query.Header.RD, RA: true},
		Questions: query.Questions,
		Answers:   answers,
	}
}

// packets returns the wire format of each message, for a handler of a fake
// upstream to return. It runs outside the goroutine of the test, so a message
// that does not encode fails the test without stopping it.
func packets(t *testing.T, messages ...Message) [][]byte {
	var encoded [][]byte

	for _, message := range messages {
		packet, err := message.Encode()
		if err != nil {
			t.Errorf("upstream failed to encode %+v: %v", message, err)
			continue
		}

		encoded = append(encoded, packet)
	}

	return encoded
}

// addressBook returns a handler for a fake upstream that behaves like the
// resolver of the last stage of the challenge. A query that asks one question
// is answered with the A record of the name in addresses, if it has one. A
// query that asks any other number of questions gets no reply at all.
func addressBook(t *testing.T, addresses map[string][]byte) func(Message) [][]byte {
	return func(query Message) [][]byte {
		if len(query.Questions) != 1 {
			return nil
		}

		question := query.Questions[0]

		address, found := addresses[question.Name]
		if !found || question.Type != TypeA || question.Class != ClassIN {
			return packets(t, replyTo(query))
		}

		return packets(t, replyTo(query, ResourceRecord{
			Name: question.Name, Type: TypeA, Class: ClassIN, TTL: 300, Data: address,
		}))
	}
}

// testContext returns a context that ends after timeout, or with the test.
func testContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)

	return ctx
}

func TestForwardingResolverReturnsAnswerOfUpstream(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, map[string][]byte{
		"codecrafters.io": {76, 76, 21, 21},
	}))
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}

	got, err := resolver.resolve(testContext(t, 2*time.Second), question, true)
	if err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	want := resolution{
		Answers: []ResourceRecord{
			{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{76, 76, 21, 21}},
		},
		RCode: RCodeNoError,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolve() = %+v, want %+v", got, want)
	}
}

func TestForwardingResolverSendsQueryWithTheOneQuestion(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, nil))
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "abc.longassdomainname.com", Type: TypeA, Class: ClassIN}

	if _, err := resolver.resolve(testContext(t, 2*time.Second), question, true); err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	queries := upstream.received()
	if len(queries) != 1 {
		t.Fatalf("upstream received %d queries, want 1", len(queries))
	}

	got := queries[0]

	// Whatever the ID is, the rest of the header is that of a plain query.
	want := Message{
		Header:    Header{ID: got.Header.ID, RD: true, QDCount: 1},
		Questions: []Question{question},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("upstream received %+v, want %+v", got, want)
	}
}

func TestForwardingResolverPassesOnRecursionDesired(t *testing.T) {
	for _, recursionDesired := range []bool{false, true} {
		upstream := startFakeUpstream(t, addressBook(t, nil))
		resolver := &forwardingResolver{addr: upstream.addr}

		question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}

		if _, err := resolver.resolve(testContext(t, 2*time.Second), question, recursionDesired); err != nil {
			t.Fatalf("RD %t: resolve returned an error: %v", recursionDesired, err)
		}

		queries := upstream.received()
		if len(queries) != 1 {
			t.Fatalf("RD %t: upstream received %d queries, want 1", recursionDesired, len(queries))
		}
		if got := queries[0].Header.RD; got != recursionDesired {
			t.Errorf("upstream received a query with RD %t, want %t", got, recursionDesired)
		}
	}
}

func TestForwardingResolverForwardsQuestionsOfAnyTypeAndClass(t *testing.T) {
	const typeTXT, classCHAOS = 16, 3

	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		return packets(t, replyTo(query, ResourceRecord{
			Name: "version.bind", Type: typeTXT, Class: classCHAOS, TTL: 0, Data: []byte("\x05hello"),
		}))
	})
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "version.bind", Type: typeTXT, Class: classCHAOS}

	got, err := resolver.resolve(testContext(t, 2*time.Second), question, false)
	if err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	want := resolution{
		Answers: []ResourceRecord{
			{Name: "version.bind", Type: typeTXT, Class: classCHAOS, TTL: 0, Data: []byte("\x05hello")},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolve() = %+v, want %+v", got, want)
	}
	if queries := upstream.received(); len(queries) != 1 || queries[0].Questions[0] != question {
		t.Errorf("upstream received %+v, want one query about %+v", queries, question)
	}
}

func TestForwardingResolverUsesIDsThatDiffer(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, nil))
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}

	for i := 0; i < 16; i++ {
		if _, err := resolver.resolve(testContext(t, 2*time.Second), question, true); err != nil {
			t.Fatalf("resolve returned an error: %v", err)
		}
	}

	ids := map[uint16]bool{}
	for _, query := range upstream.received() {
		ids[query.Header.ID] = true
	}

	// Sixteen random IDs are all the same once in 2^240 runs. Seeing fewer
	// than half of them differ is just as good as never.
	if len(ids) < 8 {
		t.Errorf("16 queries used only %d different IDs: %v", len(ids), ids)
	}
}

func TestForwardingResolverReturnsResponseCodeAndTruncation(t *testing.T) {
	const rcodeNameError = 3

	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		reply := replyTo(query)
		reply.Header.RCode = rcodeNameError
		reply.Header.TC = true

		return packets(t, reply)
	})
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "missing.example", Type: TypeA, Class: ClassIN}

	got, err := resolver.resolve(testContext(t, 2*time.Second), question, true)
	if err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	want := resolution{RCode: rcodeNameError, Truncated: true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolve() = %+v, want %+v", got, want)
	}
}

func TestForwardingResolverReturnsEveryAnswerInOrder(t *testing.T) {
	answers := []ResourceRecord{
		{Name: "www.example.com", Type: TypeCNAME, Class: ClassIN, TTL: 300, Data: []byte("\x03web\x07example\x03com\x00")},
		{Name: "web.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{93, 184, 216, 34}},
		{Name: "web.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{93, 184, 216, 35}},
	}

	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		return packets(t, replyTo(query, answers...))
	})
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "www.example.com", Type: TypeA, Class: ClassIN}

	got, err := resolver.resolve(testContext(t, 2*time.Second), question, true)
	if err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	if !reflect.DeepEqual(got.Answers, answers) {
		t.Errorf("resolve() answers = %+v, want %+v", got.Answers, answers)
	}
}

func TestForwardingResolverExpandsCompressedReply(t *testing.T) {
	// A reply laid out the way real servers send it, with every repeated name
	// replaced by a pointer:
	//
	//	12  question: www.example.com A IN
	//	33  answer: pointer to 12, CNAME, with web + pointer to 16 as its data
	//	51  answer: pointer to 45 (the data of the CNAME), A
	upstream := startFakeUpstream(t, func(query Message) [][]byte {
		return [][]byte{concat(
			[]byte{byte(query.Header.ID >> 8), byte(query.Header.ID)},
			[]byte{0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			[]byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
			[]byte("\xC0\x0C\x00\x05\x00\x01\x00\x00\x01\x2C\x00\x06\x03web\xC0\x10"),
			[]byte("\xC0\x2D\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x5D\xB8\xD8\x22"),
		)}
	})
	resolver := &forwardingResolver{addr: upstream.addr}

	question := Question{Name: "www.example.com", Type: TypeA, Class: ClassIN}

	got, err := resolver.resolve(testContext(t, 2*time.Second), question, true)
	if err != nil {
		t.Fatalf("resolve returned an error: %v", err)
	}

	// No pointer is left: they would lead nowhere outside the reply.
	want := resolution{
		Answers: []ResourceRecord{
			{Name: "www.example.com", Type: TypeCNAME, Class: ClassIN, TTL: 300, Data: []byte("\x03web\x07example\x03com\x00")},
			{Name: "web.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{93, 184, 216, 34}},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolve() = %+v, want %+v", got, want)
	}
}

func TestForwardingResolverSkipsPacketsThatAreNotTheReply(t *testing.T) {
	other := Question{Name: "other.example", Type: TypeA, Class: ClassIN}
	forged := ResourceRecord{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{6, 6, 6, 6}}
	real := ResourceRecord{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{76, 76, 21, 21}}

	tests := []struct {
		name string
		// decoy returns a packet for the upstream to send ahead of the real reply.
		decoy func(t *testing.T, query Message) []byte
	}{
		{
			name: "packet that is not a DNS message",
			decoy: func(t *testing.T, query Message) []byte {
				return []byte("not a DNS message")
			},
		},
		{
			name: "empty packet",
			decoy: func(t *testing.T, query Message) []byte {
				return []byte{}
			},
		},
		{
			name: "reply with another ID",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Header.ID++
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply to another question",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Questions = []Question{other}
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply to a question about another type",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Questions = []Question{{Name: "codecrafters.io", Type: TypeCNAME, Class: ClassIN}}
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply to a question about another class",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Questions = []Question{{Name: "codecrafters.io", Type: TypeA, Class: 3}}
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply without a question",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Questions = nil
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply with a question too many",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Questions = append(reply.Questions, other)
				return packets(t, reply)[0]
			},
		},
		{
			name: "query instead of a response",
			decoy: func(t *testing.T, query Message) []byte {
				reply := replyTo(query, forged)
				reply.Header.QR = false
				return packets(t, reply)[0]
			},
		},
		{
			name: "reply whose answer is cut short",
			decoy: func(t *testing.T, query Message) []byte {
				packet := packets(t, replyTo(query, forged))[0]
				return packet[:len(packet)-1]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := startFakeUpstream(t, func(query Message) [][]byte {
				return [][]byte{tt.decoy(t, query), packets(t, replyTo(query, real))[0]}
			})
			resolver := &forwardingResolver{addr: upstream.addr}

			question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}

			got, err := resolver.resolve(testContext(t, 2*time.Second), question, true)
			if err != nil {
				t.Fatalf("resolve returned an error: %v", err)
			}

			if want := []ResourceRecord{real}; !reflect.DeepEqual(got.Answers, want) {
				t.Errorf("resolve() answers = %+v, want %+v", got.Answers, want)
			}
		})
	}
}

func TestForwardingResolverGivesUpWhenContextEnds(t *testing.T) {
	tests := []struct {
		name   string
		handle func(t *testing.T, query Message) [][]byte
	}{
		{
			name:   "upstream that does not reply",
			handle: func(t *testing.T, query Message) [][]byte { return nil },
		},
		{
			name: "upstream that only sends replies with another ID",
			handle: func(t *testing.T, query Message) [][]byte {
				reply := replyTo(query)
				reply.Header.ID++
				return packets(t, reply, reply, reply)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := startFakeUpstream(t, func(query Message) [][]byte { return tt.handle(t, query) })
			resolver := &forwardingResolver{addr: upstream.addr}

			question := Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}

			started := time.Now()
			got, err := resolver.resolve(testContext(t, 100*time.Millisecond), question, true)
			elapsed := time.Since(started)

			if err == nil {
				t.Fatalf("resolve() = %+v, want an error", got)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("resolve() error = %v, want one that wraps context.DeadlineExceeded", err)
			}
			if elapsed < 100*time.Millisecond {
				t.Errorf("resolve gave up after %v, before its context ended", elapsed)
			}
			if elapsed > 2*time.Second {
				t.Errorf("resolve took %v to give up on a context of 100ms", elapsed)
			}
			if len(upstream.received()) != 1 {
				t.Errorf("upstream received %d queries, want 1", len(upstream.received()))
			}
		})
	}
}

func TestForwardingResolverGivesUpWhenContextIsCancelled(t *testing.T) {
	upstream := startFakeUpstream(t, func(Message) [][]byte { return nil })
	resolver := &forwardingResolver{addr: upstream.addr}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	defer cancel()

	started := time.Now()
	got, err := resolver.resolve(ctx, Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}, true)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("resolve() = %+v, want an error", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("resolve() error = %v, want one that wraps context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("resolve took %v to notice that its context was cancelled", elapsed)
	}
}

func TestForwardingResolverGivesUpAtOnceWhenContextIsAlreadyDone(t *testing.T) {
	upstream := startFakeUpstream(t, func(Message) [][]byte { return nil })
	resolver := &forwardingResolver{addr: upstream.addr}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	got, err := resolver.resolve(ctx, Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}, true)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("resolve() = %+v, want an error", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("resolve() error = %v, want one that wraps context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("resolve took %v to notice that its context was already done", elapsed)
	}

	// A query that is sent anyway arrives before this one, which shows that
	// the upstream is listening.
	if _, err := resolver.resolve(testContext(t, 100*time.Millisecond), Question{Name: "probe.example", Type: TypeA, Class: ClassIN}, true); err == nil {
		t.Fatal("resolve returned an answer from an upstream that sends none")
	}

	queries := upstream.received()
	if len(queries) != 1 || queries[0].Questions[0].Name != "probe.example" {
		t.Errorf("upstream received %+v, want only the query about probe.example", queries)
	}
}

func TestForwardingResolverFailsWhenUpstreamIsDown(t *testing.T) {
	// Find a port that nothing listens on by taking one and giving it back.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()

	resolver := &forwardingResolver{addr: addr}

	got, err := resolver.resolve(testContext(t, 300*time.Millisecond),
		Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN}, true)
	if err == nil {
		t.Fatalf("resolve() = %+v, want an error", got)
	}
}

func TestForwardingResolverRejectsQuestionThatCannotBeEncoded(t *testing.T) {
	upstream := startFakeUpstream(t, addressBook(t, nil))
	resolver := &forwardingResolver{addr: upstream.addr}

	got, err := resolver.resolve(testContext(t, 2*time.Second),
		Question{Name: "codecrafters..io", Type: TypeA, Class: ClassIN}, true)
	if err == nil {
		t.Fatalf("resolve() = %+v, want an error", got)
	}
	if queries := upstream.received(); len(queries) != 0 {
		t.Errorf("upstream received %+v, want nothing", queries)
	}
}

func TestStaticResolver(t *testing.T) {
	const typeAAAA, classCHAOS = 28, 3

	tests := []struct {
		name     string
		question Question
		want     resolution
	}{
		{
			name:     "A record in the IN class",
			question: Question{Name: "codecrafters.io", Type: TypeA, Class: ClassIN},
			want: resolution{
				Answers: []ResourceRecord{
					{Name: "codecrafters.io", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
				},
			},
		},
		{
			name:     "the answer is about the name that was asked for",
			question: Question{Name: "abc.longassdomainname.com", Type: TypeA, Class: ClassIN},
			want: resolution{
				Answers: []ResourceRecord{
					{Name: "abc.longassdomainname.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{8, 8, 8, 8}},
				},
			},
		},
		{
			name:     "no records of another type",
			question: Question{Name: "codecrafters.io", Type: typeAAAA, Class: ClassIN},
			want:     resolution{},
		},
		{
			name:     "no records of another class",
			question: Question{Name: "codecrafters.io", Type: TypeA, Class: classCHAOS},
			want:     resolution{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := staticResolver{}.resolve(context.Background(), tt.question, true)
			if err != nil {
				t.Fatalf("resolve returned an error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNewResolverWithoutAddressMakesAnswersUp(t *testing.T) {
	got, err := newResolver("")
	if err != nil {
		t.Fatalf("newResolver returned an error: %v", err)
	}

	if _, ok := got.(staticResolver); !ok {
		t.Errorf("newResolver(\"\") = %T, want a staticResolver", got)
	}
}

func TestNewResolverWithAddressForwards(t *testing.T) {
	tests := []struct {
		address  string
		wantIP   net.IP
		wantPort int
	}{
		{address: "127.0.0.1:5354", wantIP: net.IPv4(127, 0, 0, 1), wantPort: 5354},
		{address: "8.8.8.8:53", wantIP: net.IPv4(8, 8, 8, 8), wantPort: 53},
		{address: "[::1]:5353", wantIP: net.IPv6loopback, wantPort: 5353},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got, err := newResolver(tt.address)
			if err != nil {
				t.Fatalf("newResolver returned an error: %v", err)
			}

			forwarding, ok := got.(*forwardingResolver)
			if !ok {
				t.Fatalf("newResolver(%q) = %T, want a *forwardingResolver", tt.address, got)
			}
			if !forwarding.addr.IP.Equal(tt.wantIP) || forwarding.addr.Port != tt.wantPort {
				t.Errorf("resolver forwards to %s, want %s port %d", forwarding.addr, tt.wantIP, tt.wantPort)
			}
		})
	}
}

func TestNewResolverRejectsInvalidAddress(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1",       // no port
		"127.0.0.1:",      // empty port
		"127.0.0.1:99999", // port out of range
		"127.0.0.1:53:53", // too many colons
		"[::1",            // unfinished IPv6 address
	} {
		t.Run(address, func(t *testing.T) {
			if got, err := newResolver(address); err == nil {
				t.Errorf("newResolver(%q) = %+v, want an error", address, got)
			}
		})
	}
}
