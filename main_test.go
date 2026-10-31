package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

var errUpstreamDown = errors.New("upstream down")

type upstreamHandler func(ctx context.Context, query *dns.Msg) ([]byte, error)

type fakeUpstream struct {
	mu       sync.Mutex
	handlers map[string]upstreamHandler
	received map[string][][]byte
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{
		handlers: make(map[string]upstreamHandler),
		received: make(map[string][][]byte),
	}
}

func (f *fakeUpstream) Exchange(ctx context.Context, host, _ string, rawMsg []byte) ([]byte, error) {
	f.mu.Lock()
	f.received[host] = append(f.received[host], bytes.Clone(rawMsg))
	h := f.handlers[host]
	f.mu.Unlock()

	if h == nil {
		return nil, errUpstreamDown
	}
	query := new(dns.Msg)
	if err := query.Unpack(rawMsg); err != nil {
		return nil, err
	}
	return h(ctx, query)
}

func (f *fakeUpstream) handle(host string, h upstreamHandler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[host] = h
}

func (f *fakeUpstream) calls(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.received[host])
}

func (f *fakeUpstream) lastQuery(t *testing.T, host string) ([]byte, *dns.Msg) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	received := f.received[host]
	if len(received) == 0 {
		t.Fatalf("no query received by %s", host)
	}
	raw := received[len(received)-1]
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("unpack upstream query: %v", err)
	}
	return raw, msg
}

func failing(context.Context, *dns.Msg) ([]byte, error) {
	return nil, errUpstreamDown
}

func blocking(ctx context.Context, _ *dns.Msg) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func replying(build func(reply *dns.Msg)) upstreamHandler {
	return func(_ context.Context, query *dns.Msg) ([]byte, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.RecursionAvailable = true
		build(reply)
		return reply.Pack()
	}
}

func answering(ip string, ttl uint32) upstreamHandler {
	return replying(func(reply *dns.Msg) {
		reply.Answer = append(reply.Answer, aRecord(reply.Question[0].Name, ip, ttl))
	})
}

func delayed(d time.Duration, h upstreamHandler) upstreamHandler {
	return func(ctx context.Context, query *dns.Msg) ([]byte, error) {
		select {
		case <-time.After(d):
			return h(ctx, query)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func aRecord(name, ip string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

func setup(t *testing.T) {
	t.Helper()
	dnsCache = new(sync.Map)
	dnsCacheSize.Store(0)
	sfGroup = new(singleflight.Group)
	clientConfigs = nil
	blockList.Store(NewTrie())
	skipList.Store(NewTrie())
	userAgents.Store(&[]string{"test-agent"})
	enabledLog = false
}

func addClientConfig(upstream Upstream, hosts ...string) []*Target {
	dnsConfigs := make([]DNSConfig, 0, len(hosts))
	for i, host := range hosts {
		dnsConfigs = append(dnsConfigs, DNSConfig{ID: i, Host: host})
	}
	targets := newTargets(dnsConfigs)
	clientConfigs = append(clientConfigs, ClientConfig{Upstream: upstream, Targets: targets})
	return targets
}

func hostName(i int) string {
	return "host" + strconv.Itoa(i) + ".example.com."
}

func newQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

func ask(t *testing.T, msg *dns.Msg) *dns.Msg {
	t.Helper()
	rawMsg, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	respRawMsg, err := resolve(t.Context(), rawMsg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respRawMsg); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return respMsg
}

func assertA(t *testing.T, respMsg *dns.Msg, ip string) {
	t.Helper()
	if respMsg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[respMsg.Rcode])
	}
	if len(respMsg.Answer) != 1 {
		t.Fatalf("answer = %v, want one A record", respMsg.Answer)
	}
	a, ok := respMsg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP(ip)) {
		t.Fatalf("answer = %v, want %s", respMsg.Answer[0], ip)
	}
}

func assertCalls(t *testing.T, f *fakeUpstream, host string, want int) {
	t.Helper()
	if got := f.calls(host); got != want {
		t.Fatalf("calls to %s = %d, want %d", host, got, want)
	}
}

func countOPT(msg *dns.Msg) int {
	var n int
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			n++
		}
	}
	return n
}

func assertSanitized(t *testing.T, raw []byte, query *dns.Msg) {
	t.Helper()
	if query.Id != 0 {
		t.Errorf("id = %#x, want 0", query.Id)
	}
	if !query.RecursionDesired || query.CheckingDisabled || query.AuthenticatedData {
		t.Errorf("flags rd=%t cd=%t ad=%t, want only rd", query.RecursionDesired, query.CheckingDisabled, query.AuthenticatedData)
	}
	if len(query.Extra) != 1 || countOPT(query) != 1 {
		t.Fatalf("extra = %v, want exactly one OPT", query.Extra)
	}
	opt := query.IsEdns0()
	if opt.UDPSize() != 1232 || opt.Do() {
		t.Errorf("opt udp size = %d do = %t, want 1232 and false", opt.UDPSize(), opt.Do())
	}
	if len(opt.Option) != 1 {
		t.Fatalf("opt options = %v, want only padding", opt.Option)
	}
	if _, ok := opt.Option[0].(*dns.EDNS0_PADDING); !ok {
		t.Errorf("opt option = %T, want padding", opt.Option[0])
	}
	if len(raw)%128 != 0 {
		t.Errorf("query length = %d, want multiple of 128", len(raw))
	}
}

func noisyReply(reply *dns.Msg) {
	reply.Answer = append(reply.Answer, aRecord(reply.Question[0].Name, "192.0.2.1", 300))
	reply.SetEdns0(4096, true)
	opt := reply.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 24, Address: net.ParseIP("198.51.100.0").To4()},
		&dns.EDNS0_PADDING{Padding: make([]byte, 40)},
	)
}

func TestSanitizeUpstreamQuery(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", replying(noisyReply))
	addClientConfig(f, "s0")

	msg := newQuery("ExAmple.COM", dns.TypeA)
	msg.Id = 0x1234
	msg.CheckingDisabled = true
	msg.SetEdns0(4096, true)
	opt := msg.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("203.0.113.0").To4()},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"},
	)

	respMsg := ask(t, msg)
	raw, query := f.lastQuery(t, "s0")
	assertSanitized(t, raw, query)

	assertA(t, respMsg, "192.0.2.1")
	if respMsg.Id != 0x1234 {
		t.Errorf("response id = %#x, want 0x1234", respMsg.Id)
	}
	if len(respMsg.Question) != 1 || respMsg.Question[0] != msg.Question[0] {
		t.Errorf("response question = %v, want %v", respMsg.Question, msg.Question)
	}
	if countOPT(respMsg) != 1 {
		t.Fatalf("response extra = %v, want exactly one OPT", respMsg.Extra)
	}
	if respOPT := respMsg.IsEdns0(); len(respOPT.Option) != 0 || respOPT.Do() {
		t.Errorf("response opt = %v, want no options", respOPT)
	}
}

func TestSanitizeUpstreamQueryWithoutEDNS(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", replying(noisyReply))
	addClientConfig(f, "s0")

	respMsg := ask(t, newQuery("example.com", dns.TypeA))
	raw, query := f.lastQuery(t, "s0")
	assertSanitized(t, raw, query)

	assertA(t, respMsg, "192.0.2.1")
	if countOPT(respMsg) != 0 {
		t.Errorf("response extra = %v, want no OPT", respMsg.Extra)
	}
}

func TestSanitizePaddingLengths(t *testing.T) {
	for _, name := range []string{"a.", "example.com.", "a-much-longer-label-for-padding.sub.example.org.", strings.Repeat("x", 60) + ".example."} {
		query, err := buildUpstreamQuery(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		if err != nil {
			t.Fatalf("build %s: %v", name, err)
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(query); err != nil {
			t.Fatalf("unpack %s: %v", name, err)
		}
		assertSanitized(t, query, msg)
	}
}

func assertRcode(t *testing.T, respMsg *dns.Msg, want int) {
	t.Helper()
	if respMsg.Rcode != want {
		t.Fatalf("rcode = %s, want %s", dns.RcodeToString[respMsg.Rcode], dns.RcodeToString[want])
	}
}

func TestPerAttemptTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", blocking)
		f.handle("s1", answering("192.0.2.2", 300))
		addClientConfig(f, "s0", "s1")

		start := time.Now()
		assertA(t, ask(t, newQuery("example.com", dns.TypeA)), "192.0.2.2")
		if elapsed := time.Since(start); elapsed != attemptTimeout {
			t.Fatalf("elapsed = %s, want %s", elapsed, attemptTimeout)
		}
		assertCalls(t, f, "s0", 1)
		assertCalls(t, f, "s1", 1)
	})
}

func TestProxyFailover(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("a0", failing)
	f.handle("a1", failing)
	f.handle("b0", answering("192.0.2.3", 300))
	addClientConfig(f, "a0", "a1")
	addClientConfig(f, "b0")

	for i := range 20 {
		assertA(t, ask(t, newQuery(hostName(i), dns.TypeA)), "192.0.2.3")
	}
	assertCalls(t, f, "b0", 20)
}

func TestHealthCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("t0", failing)
		f.handle("t1", answering("192.0.2.2", 300))
		targets := addClientConfig(f, "t0", "t1")

		for i := range failureThreshold {
			assertA(t, ask(t, newQuery(hostName(i), dns.TypeA)), "192.0.2.2")
		}
		assertCalls(t, f, "t0", failureThreshold)

		time.Sleep(failureCooldown - time.Second)
		assertA(t, ask(t, newQuery(hostName(10), dns.TypeA)), "192.0.2.2")
		assertCalls(t, f, "t0", failureThreshold)

		time.Sleep(time.Second)
		f.handle("t0", answering("192.0.2.1", 300))
		assertA(t, ask(t, newQuery(hostName(11), dns.TypeA)), "192.0.2.1")
		assertCalls(t, f, "t0", failureThreshold+1)
		if failures := targets[0].failures.Load(); failures != 0 {
			t.Fatalf("failures = %d, want 0", failures)
		}
	})
}

func TestHealthAllInCooldownStillTried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("t0", failing)
		f.handle("t1", failing)
		targets := addClientConfig(f, "t0", "t1")

		for i := range failureThreshold {
			assertRcode(t, ask(t, newQuery(hostName(i), dns.TypeA)), dns.RcodeServerFailure)
		}
		for _, target := range targets {
			if target.available(time.Now()) {
				t.Fatalf("target %s available, want in cooldown", target.Host)
			}
		}

		f.handle("t1", answering("192.0.2.2", 300))
		assertA(t, ask(t, newQuery(hostName(10), dns.TypeA)), "192.0.2.2")
		assertCalls(t, f, "t0", failureThreshold+1)
		assertCalls(t, f, "t1", failureThreshold+1)
	})
}

func soaRecord(zone string, ttl, minttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minttl,
	}
}

func negativeReply(rcode int, ttl, minttl uint32) upstreamHandler {
	return replying(func(reply *dns.Msg) {
		reply.Rcode = rcode
		reply.Ns = append(reply.Ns, soaRecord("example.com.", ttl, minttl))
	})
}

func assertNegative(t *testing.T, respMsg *dns.Msg, rcode int, soaTTL uint32) {
	t.Helper()
	assertRcode(t, respMsg, rcode)
	if len(respMsg.Answer) != 0 {
		t.Fatalf("answer = %v, want empty", respMsg.Answer)
	}
	if len(respMsg.Ns) != 1 {
		t.Fatalf("authority = %v, want one SOA", respMsg.Ns)
	}
	soa, ok := respMsg.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority = %v, want SOA", respMsg.Ns[0])
	}
	if soa.Hdr.Ttl != soaTTL {
		t.Fatalf("soa ttl = %d, want %d", soa.Hdr.Ttl, soaTTL)
	}
}

func TestNegativeCache(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{"NXDOMAIN", dns.TypeA, dns.RcodeNameError},
		{"NODATA", dns.TypeAAAA, dns.RcodeSuccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				setup(t)
				f := newFakeUpstream()
				f.handle("s0", negativeReply(tc.rcode, 300, 60))
				addClientConfig(f, "s0")

				assertNegative(t, ask(t, newQuery("missing.example.com", tc.qtype)), tc.rcode, 300)
				assertCalls(t, f, "s0", 1)

				time.Sleep(10 * time.Second)
				assertNegative(t, ask(t, newQuery("missing.example.com", tc.qtype)), tc.rcode, 50)
				assertCalls(t, f, "s0", 1)

				time.Sleep(50 * time.Second)
				assertNegative(t, ask(t, newQuery("missing.example.com", tc.qtype)), tc.rcode, 300)
				assertCalls(t, f, "s0", 2)
			})
		})
	}
}

func TestNegativeCacheTTLCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", negativeReply(dns.RcodeNameError, 86400, 86400))
		addClientConfig(f, "s0")

		assertNegative(t, ask(t, newQuery("missing.example.com", dns.TypeA)), dns.RcodeNameError, 86400)
		time.Sleep(3599 * time.Second)
		assertNegative(t, ask(t, newQuery("missing.example.com", dns.TypeA)), dns.RcodeNameError, 1)
		assertCalls(t, f, "s0", 1)

		time.Sleep(time.Second)
		ask(t, newQuery("missing.example.com", dns.TypeA))
		assertCalls(t, f, "s0", 2)
	})
}

func TestNegativeCacheSkipsUncacheable(t *testing.T) {
	cases := map[string]upstreamHandler{
		"no SOA": replying(func(reply *dns.Msg) { reply.Rcode = dns.RcodeNameError }),
		"SERVFAIL": replying(func(reply *dns.Msg) {
			reply.Rcode = dns.RcodeServerFailure
			reply.Ns = append(reply.Ns, soaRecord("example.com.", 300, 60))
		}),
		"truncated": replying(func(reply *dns.Msg) {
			reply.Truncated = true
			reply.Answer = append(reply.Answer, aRecord(reply.Question[0].Name, "192.0.2.1", 300))
		}),
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			setup(t)
			f := newFakeUpstream()
			f.handle("s0", handler)
			addClientConfig(f, "s0")

			ask(t, newQuery("missing.example.com", dns.TypeA))
			ask(t, newQuery("missing.example.com", dns.TypeA))
			assertCalls(t, f, "s0", 2)
		})
	}
}

func assertTTLs(t *testing.T, respMsg *dns.Msg, want uint32) {
	t.Helper()
	for _, rr := range slices.Concat(respMsg.Answer, respMsg.Ns) {
		if rr.Header().Ttl != want {
			t.Fatalf("ttl of %v = %d, want %d", rr, rr.Header().Ttl, want)
		}
	}
}

func TestServeStaleOnFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", replying(func(reply *dns.Msg) {
			name := reply.Question[0].Name
			reply.Answer = append(reply.Answer, aRecord(name, "192.0.2.1", 300), aRecord(name, "192.0.2.2", 600))
		}))
		addClientConfig(f, "s0")

		ask(t, newQuery("example.com", dns.TypeA))
		f.handle("s0", failing)

		time.Sleep(maxStale - time.Second)
		respMsg := ask(t, newQuery("example.com", dns.TypeA))
		assertRcode(t, respMsg, dns.RcodeSuccess)
		if len(respMsg.Answer) != 2 {
			t.Fatalf("answer = %v, want two A records", respMsg.Answer)
		}
		assertTTLs(t, respMsg, staleTTL)
		assertCalls(t, f, "s0", 2)
	})
}

func TestServeStaleOnErrorRcode(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				setup(t)
				f := newFakeUpstream()
				f.handle("s0", negativeReply(dns.RcodeNameError, 300, 60))
				addClientConfig(f, "s0")

				ask(t, newQuery("missing.example.com", dns.TypeA))
				f.handle("s0", replying(func(reply *dns.Msg) { reply.Rcode = rcode }))

				time.Sleep(time.Hour)
				assertNegative(t, ask(t, newQuery("missing.example.com", dns.TypeA)), dns.RcodeNameError, staleTTL)
			})
		})
	}
}

func TestServeStaleRecheckDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 300))
		addClientConfig(f, "s0")

		ask(t, newQuery("example.com", dns.TypeA))
		f.handle("s0", delayed(5*time.Second, failing))
		time.Sleep(time.Hour)

		start := time.Now()
		assertA(t, ask(t, newQuery("example.com", dns.TypeA)), "192.0.2.1")
		if elapsed := time.Since(start); elapsed != staleClientTimeout {
			t.Fatalf("elapsed = %s, want %s", elapsed, staleClientTimeout)
		}
		time.Sleep(5 * time.Second)
		assertCalls(t, f, "s0", 2)

		start = time.Now()
		respMsg := ask(t, newQuery("example.com", dns.TypeA))
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("elapsed = %s, want stale answer without waiting", elapsed)
		}
		assertA(t, respMsg, "192.0.2.1")
		assertTTLs(t, respMsg, staleTTL)
		assertCalls(t, f, "s0", 2)

		time.Sleep(staleRecheckDelay)
		ask(t, newQuery("example.com", dns.TypeA))
		time.Sleep(5 * time.Second)
		assertCalls(t, f, "s0", 3)
	})
}

func TestServeStaleOnSlowUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 300))
		addClientConfig(f, "s0")

		ask(t, newQuery("example.com", dns.TypeA))
		time.Sleep(301 * time.Second)
		f.handle("s0", delayed(5*time.Second, answering("192.0.2.2", 600)))

		start := time.Now()
		respMsg := ask(t, newQuery("example.com", dns.TypeA))
		if elapsed := time.Since(start); elapsed != staleClientTimeout {
			t.Fatalf("elapsed = %s, want %s", elapsed, staleClientTimeout)
		}
		assertA(t, respMsg, "192.0.2.1")
		assertTTLs(t, respMsg, staleTTL)

		time.Sleep(5 * time.Second)
		respMsg = ask(t, newQuery("example.com", dns.TypeA))
		assertA(t, respMsg, "192.0.2.2")
		assertTTLs(t, respMsg, 598)
		assertCalls(t, f, "s0", 2)
	})
}

func TestServeStaleLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 300))
		addClientConfig(f, "s0")

		ask(t, newQuery("example.com", dns.TypeA))
		f.handle("s0", failing)

		time.Sleep(300*time.Second + maxStale)
		assertRcode(t, ask(t, newQuery("example.com", dns.TypeA)), dns.RcodeServerFailure)
	})
}

func TestBlocklistBeforeCache(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", answering("192.0.2.1", 300))
	addClientConfig(f, "s0")

	assertA(t, ask(t, newQuery("example.com", dns.TypeA)), "192.0.2.1")
	assertCalls(t, f, "s0", 1)

	trie := NewTrie()
	trie.Insert("example.com.")
	blockList.Store(trie)

	assertA(t, ask(t, newQuery("example.com", dns.TypeA)), "0.0.0.0")
	assertCalls(t, f, "s0", 1)
}

func TestPositiveCacheDecrementsTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 300))
		addClientConfig(f, "s0")

		assertA(t, ask(t, newQuery("example.com", dns.TypeA)), "192.0.2.1")
		assertCalls(t, f, "s0", 1)

		time.Sleep(100 * time.Second)
		respMsg := ask(t, newQuery("example.com", dns.TypeA))
		assertA(t, respMsg, "192.0.2.1")
		assertCalls(t, f, "s0", 1)
		if ttl := respMsg.Answer[0].Header().Ttl; ttl != 200 {
			t.Fatalf("ttl = %d, want 200", ttl)
		}

		time.Sleep(199*time.Second + 500*time.Millisecond)
		respMsg = ask(t, newQuery("example.com", dns.TypeA))
		assertCalls(t, f, "s0", 1)
		if ttl := respMsg.Answer[0].Header().Ttl; ttl != 1 {
			t.Fatalf("ttl = %d, want 1", ttl)
		}
	})
}

func TestNegativeCacheCNAMENoData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", replying(func(reply *dns.Msg) {
			reply.Answer = append(reply.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 86400},
				Target: "cdn.example.net.",
			})
			reply.Ns = append(reply.Ns, soaRecord("example.net.", 300, 60))
		}))
		addClientConfig(f, "s0")

		ask(t, newQuery("www.example.com", dns.TypeAAAA))
		time.Sleep(59 * time.Second)
		respMsg := ask(t, newQuery("www.example.com", dns.TypeAAAA))
		assertCalls(t, f, "s0", 1)
		if len(respMsg.Answer) != 1 || len(respMsg.Ns) != 1 {
			t.Fatalf("response = %v, want CNAME answer and SOA authority", respMsg)
		}

		time.Sleep(time.Second)
		ask(t, newQuery("www.example.com", dns.TypeAAAA))
		assertCalls(t, f, "s0", 2)
	})
}

func TestNegativeCacheCNAMEWithoutSOA(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", replying(func(reply *dns.Msg) {
		reply.Answer = append(reply.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 86400},
			Target: "cdn.example.net.",
		})
	}))
	addClientConfig(f, "s0")

	ask(t, newQuery("www.example.com", dns.TypeAAAA))
	ask(t, newQuery("www.example.com", dns.TypeAAAA))
	assertCalls(t, f, "s0", 2)
}

func TestCacheKeySeparatesClass(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", replying(func(reply *dns.Msg) {
		q := reply.Question[0]
		reply.Answer = append(reply.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: q.Qclass, Ttl: 300},
			Txt: []string{dns.Class(q.Qclass).String()},
		})
	}))
	addClientConfig(f, "s0")

	ask(t, newQuery("example.com", dns.TypeTXT))
	chaos := newQuery("example.com", dns.TypeTXT)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	respMsg := ask(t, chaos)
	assertCalls(t, f, "s0", 2)
	txt, ok := respMsg.Answer[0].(*dns.TXT)
	if !ok || txt.Txt[0] != "CH" {
		t.Fatalf("answer = %v, want CH TXT", respMsg.Answer)
	}
}

func TestPositiveCacheTTLCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 30*24*3600))
		addClientConfig(f, "s0")

		ask(t, newQuery("example.com", dns.TypeA))
		time.Sleep(time.Second)
		respMsg := ask(t, newQuery("example.com", dns.TypeA))
		assertTTLs(t, respMsg, maxCacheTTL-1)
		assertCalls(t, f, "s0", 1)

		time.Sleep(maxCacheTTL*time.Second - time.Second)
		ask(t, newQuery("example.com", dns.TypeA))
		assertCalls(t, f, "s0", 2)
	})
}

func TestPositiveCacheSkipsHighBitTTL(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", answering("192.0.2.1", 0xFFFFFFF0))
	addClientConfig(f, "s0")

	ask(t, newQuery("example.com", dns.TypeA))
	ask(t, newQuery("example.com", dns.TypeA))
	assertCalls(t, f, "s0", 2)
}

func TestCacheCapacity(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", answering("192.0.2.1", 300))
	addClientConfig(f, "s0")

	ask(t, newQuery("cached.example.com", dns.TypeA))
	dnsCacheSize.Store(maxCacheEntries)

	ask(t, newQuery("new.example.com", dns.TypeA))
	ask(t, newQuery("new.example.com", dns.TypeA))
	assertCalls(t, f, "s0", 3)

	ask(t, newQuery("cached.example.com", dns.TypeA))
	assertCalls(t, f, "s0", 3)
}

func TestEvictCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		f := newFakeUpstream()
		f.handle("s0", answering("192.0.2.1", 300))
		addClientConfig(f, "s0")

		ask(t, newQuery("a.example.com", dns.TypeA))
		time.Sleep(time.Hour)
		ask(t, newQuery("b.example.com", dns.TypeA))

		evictCache(time.Now())
		if size := dnsCacheSize.Load(); size != 2 {
			t.Fatalf("size = %d, want 2 before stale limit", size)
		}

		dnsCacheSize.Store(maxCacheEntries)
		evictCache(time.Now())
		if _, ok := dnsCache.Load(cacheKey(newQuery("a.example.com", dns.TypeA).Question[0])); ok {
			t.Fatal("expired entry kept while cache is full")
		}
		if _, ok := dnsCache.Load(cacheKey(newQuery("b.example.com", dns.TypeA).Question[0])); !ok {
			t.Fatal("fresh entry evicted")
		}

		dnsCacheSize.Store(1)
		time.Sleep(maxStale + 300*time.Second)
		evictCache(time.Now())
		if size := dnsCacheSize.Load(); size != 0 {
			t.Fatalf("size = %d, want 0 after stale limit", size)
		}
	})
}

func TestHealthConcurrentFailuresCountOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup(t)
		release := make(chan struct{})
		f := newFakeUpstream()
		f.handle("t0", func(context.Context, *dns.Msg) ([]byte, error) {
			<-release
			return nil, errUpstreamDown
		})
		f.handle("t1", answering("192.0.2.2", 300))
		targets := addClientConfig(f, "t0", "t1")

		var wg sync.WaitGroup
		for i := range failureThreshold {
			wg.Go(func() {
				rawMsg, err := newQuery(hostName(i), dns.TypeA).Pack()
				if err != nil {
					t.Errorf("pack query: %v", err)
					return
				}
				if _, err := resolve(t.Context(), rawMsg); err != nil {
					t.Errorf("resolve: %v", err)
				}
			})
		}
		time.Sleep(time.Second)
		close(release)
		wg.Wait()

		if failures := targets[0].failures.Load(); failures != 1 {
			t.Fatalf("failures = %d, want 1", failures)
		}
		if !targets[0].available(time.Now()) {
			t.Fatal("target in cooldown after one burst of overlapping failures")
		}
	})
}

func TestServerFailureKeepsOPT(t *testing.T) {
	setup(t)
	f := newFakeUpstream()
	f.handle("s0", failing)
	addClientConfig(f, "s0")

	msg := newQuery("example.com", dns.TypeA)
	msg.SetEdns0(4096, false)
	respMsg := ask(t, msg)
	assertRcode(t, respMsg, dns.RcodeServerFailure)
	if countOPT(respMsg) != 1 || len(respMsg.IsEdns0().Option) != 0 {
		t.Fatalf("extra = %v, want one empty OPT", respMsg.Extra)
	}
}
