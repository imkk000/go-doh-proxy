package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

var (
	noProxyServers     bool
	httpMode           bool
	blocklistFile      string
	skipListFile       string
	certFile, keyFile  string
	udpAddr            string
	userAgentFile      string
	dnsServers         []DNSConfig
	proxyServers       []Config
	enabledLog         bool
	addr               = "127.0.0.1:9553"
	defaultDNSResolver = "host.docker.internal:53"
	defaultUserAgent   = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.10 Safari/605.1.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.3",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Trailer/93.3.8652.5",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.1958",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3",
	}
	defaultDNSServers = []DNSConfig{
		{0, "https://dns.quad9.net/dns-query", TypeDefault},
		{1, "https://all.dns.mullvad.net/dns-query", TypeDefault},
		{2, "https://security.cloudflare-dns.com/dns-query", TypeDefault},
	}
	supportedQtypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeSRV, dns.TypeTXT}
)

var (
	blockList     atomic.Pointer[Trie]
	skipList      atomic.Pointer[Trie]
	userAgents    atomic.Pointer[[]string]
	clientConfigs []ClientConfig
	sfGroup       = new(singleflight.Group)
	dnsCache      = new(sync.Map)
	skipUDPClient = &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	skipTCPClient = &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
)

var errInvalidQuery = errors.New("invalid query message")

const upstreamTimeout = 30 * time.Second

type DNSCacheRR struct {
	RR     dns.RR
	Expiry time.Time
}

func parseFlags(args []string) error {
	flags := flag.NewFlagSet("doh-server", flag.ContinueOnError)
	flags.BoolVar(&httpMode, "http", httpMode, "set http mode")
	flags.StringVar(&addr, "addr", addr, "set address")
	flags.StringVar(&udpAddr, "udp", "", "set udp address")
	flags.StringVar(&certFile, "cert", "", "set cert.pem file")
	flags.StringVar(&keyFile, "key", "", "set key.pem file")
	flags.StringVar(&skipListFile, "skiplist", "", "set skip list file")
	flags.StringVar(&blocklistFile, "blocklist", "", "set blocklist file")
	flags.StringVar(&userAgentFile, "ua", "", "set user agent list file")
	flags.StringVar(&defaultDNSResolver, "default-resolver", defaultDNSResolver, "set default dns server")
	flags.BoolVar(&enabledLog, "log", enabledLog, "enable log")
	flags.Func("proxy", "set proxy servers to query dns using random routes", func(s string) error {
		if noProxyServers {
			return nil
		}
		if len(s) == 0 {
			return errors.New("proxy server cannot be empty")
		}
		if s == "off" {
			noProxyServers = true
			proxyServers = nil
			return nil
		}

		var configType Type
		if strings.HasPrefix(s, TorPrefix) {
			configType = TypeTor
			s = strings.TrimPrefix(s, TorPrefix)
		}
		proxyServers = append(proxyServers, Config{s, configType})

		return nil
	})
	flags.Func("dns", "set doh dns server", func(s string) error {
		if len(s) == 0 {
			return errors.New("dns server cannot be empty")
		}

		ss := strings.Split(s, ";")
		if len(ss) < 2 {
			return fmt.Errorf("invalid format: %q", s)
		}
		idx, err := strconv.Atoi(ss[0])
		if err != nil {
			return fmt.Errorf("cannot parse index: %q %w", ss[0], err)
		}
		u, err := url.Parse(ss[1])
		if err != nil {
			return fmt.Errorf("cannot parse url: %q %w", ss[1], err)
		}

		var configType Type
		if strings.HasSuffix(u.Host, OnionSuffix) {
			configType = TypeTor
		}
		dnsServers = append(dnsServers, DNSConfig{
			ID:   idx,
			Host: u.String(),
			Type: configType,
		})

		return nil
	})
	if err := flags.Parse(args); err != nil {
		return err
	}

	if len(proxyServers) == 0 {
		noProxyServers = true
	}
	if len(dnsServers) == 0 {
		dnsServers = defaultDNSServers
	}
	slices.SortFunc(dnsServers, func(a, b DNSConfig) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		slog.Error("run server", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if err := parseFlags(args); err != nil {
		return err
	}

	if !httpMode && (len(certFile) == 0 || len(keyFile) == 0) {
		return errors.New("empty keys file path")
	}

	if err := loadConfigs(); err != nil {
		return fmt.Errorf("load configuration file: %w", err)
	}

	configs, err := newClientConfigs()
	if err != nil {
		return err
	}
	clientConfigs = configs

	if enabledLog {
		slog.Info("print user agents", "ua", userAgents.Load())
		slog.Info("print proxy servers", "servers", proxyServers)
		slog.Info("print dns servers", "servers", dnsServers)
		slog.Info("print client configs", "clients", clientConfigs)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(udpAddr) > 0 {
		conn, err := listenUDP(udpAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		go serveUDP(conn)
	}

	go reloadConfig(ctx)
	go evictDNSCache(ctx)

	return startHTTPServer(ctx)
}

func newClientConfigs() ([]ClientConfig, error) {
	if noProxyServers {
		dnsServers = slices.DeleteFunc(dnsServers, isTorDNS)
		if len(dnsServers) == 0 {
			return nil, errors.New("no dns servers available without proxy")
		}
		dialer := &net.Dialer{Timeout: upstreamTimeout, KeepAlive: 30 * time.Second}
		return []ClientConfig{{
			DNSConfigs: dnsServers,
			Client: newHTTPClient(&http.Transport{
				Proxy:       http.ProxyFromEnvironment,
				DialContext: dialer.DialContext,
			}),
		}}, nil
	}

	configs := make([]ClientConfig, 0, len(proxyServers))
	for _, proxyServer := range proxyServers {
		dial, err := proxy.SOCKS5("tcp", proxyServer.Host, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("connect to proxy server %q: %w", proxyServer.Host, err)
		}
		dialer, ok := dial.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy server %q does not support context dialer", proxyServer.Host)
		}
		dnsConfigs := slices.Clone(dnsServers)
		if proxyServer.Type == TypeDefault {
			dnsConfigs = slices.DeleteFunc(dnsConfigs, isTorDNS)
		}
		if len(dnsConfigs) == 0 {
			return nil, fmt.Errorf("no dns servers available for proxy server %q", proxyServer.Host)
		}
		configs = append(configs, ClientConfig{
			DNSConfigs: dnsConfigs,
			Client:     newHTTPClient(&http.Transport{DialContext: dialer.DialContext}),
		})
	}

	return configs, nil
}

func isTorDNS(d DNSConfig) bool {
	return d.Type == TypeTor
}

func newHTTPClient(transport *http.Transport) *http.Client {
	transport.ForceAttemptHTTP2 = true
	transport.TLSHandshakeTimeout = 15 * time.Second
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   upstreamTimeout,
	}
}

func startHTTPServer(ctx context.Context) error {
	e := echo.New()

	if enabledLog {
		enableHTTPLog(e)
	}

	g := e.Group("dns-query")
	g.POST("", echoPOST)
	g.GET("", echoGET)

	sc := echo.StartConfig{
		Address:    addr,
		HideBanner: true,
		HidePort:   true,
	}
	if httpMode {
		return sc.Start(ctx, e)
	}
	return sc.StartTLS(ctx, e, certFile, keyFile)
}

func reloadConfig(ctx context.Context) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			slog.Info("reloading configuration files")
			if err := loadConfigs(); err != nil {
				slog.Error("reloading configuration files", "error", err)
			}
		}
	}
}

func loadConfigs() error {
	newSkipList, err := readConfigFile(skipListFile)
	if err != nil {
		return fmt.Errorf("read skip list: %w", err)
	}

	newBlockList, err := readConfigFile(blocklistFile)
	if err != nil {
		return fmt.Errorf("read blocklist: %w", err)
	}

	newUserAgents := defaultUserAgent
	if len(userAgentFile) > 0 {
		newUserAgents, err = readUserAgentFile(userAgentFile)
		if err != nil {
			return fmt.Errorf("read user agent file: %w", err)
		}
	}

	skipList.Store(newSkipList)
	blockList.Store(newBlockList)
	userAgents.Store(&newUserAgents)

	return nil
}

func readUserAgentFile(filename string) ([]string, error) {
	fs, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fs.Close()

	var agents []string
	scanner := bufio.NewScanner(fs)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.HasSuffix(line, ".") {
			line += "0"
		}
		agents = append(agents, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(agents) == 0 {
		return nil, errors.New("empty user agents")
	}

	return agents, nil
}

func readConfigFile(filename string) (*Trie, error) {
	trie := NewTrie()
	if len(filename) == 0 {
		return trie, nil
	}
	fs, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open %s filename: %w", filename, err)
	}
	defer fs.Close()

	scanner := bufio.NewScanner(fs)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		trie.Insert(dns.Fqdn(fields[len(fields)-1]))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s filename: %w", filename, err)
	}

	return trie, nil
}

func resolve(ctx context.Context, rawMsg []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidQuery, err)
	}
	return answer(ctx, msg, rawMsg), nil
}

func answer(ctx context.Context, msg *dns.Msg, rawMsg []byte) []byte {
	if enabledLog {
		slog.Info("query", "q", msg.Question)
	}

	if !isSupportedQuery(msg) {
		return packResponse(msg, newReply(msg), "unsupported")
	}

	if skipList.Load().Match(msg.Question[0].Name) {
		return resolveSkipped(ctx, msg)
	}

	if cached, hit := getCache(msg); hit {
		return packResponse(msg, cached, "cache")
	}

	if blocked, isBlocked := answerBlocklist(msg); isBlocked {
		return packResponse(msg, blocked, "blocklist")
	}

	return resolveUpstream(ctx, msg, rawMsg)
}

func isSupportedQuery(msg *dns.Msg) bool {
	return len(msg.Question) == 1 &&
		msg.Question[0].Qclass != 0 &&
		slices.Contains(supportedQtypes, msg.Question[0].Qtype)
}

func resolveSkipped(ctx context.Context, msg *dns.Msg) []byte {
	respMsg, _, err := skipUDPClient.ExchangeContext(ctx, msg, defaultDNSResolver)
	if err == nil && respMsg.Truncated {
		respMsg, _, err = skipTCPClient.ExchangeContext(ctx, msg, defaultDNSResolver)
	}
	if err != nil {
		return serverFailure(msg, err, "skip domain")
	}
	return packResponse(msg, respMsg, "skiplist")
}

func resolveUpstream(ctx context.Context, msg *dns.Msg, rawMsg []byte) []byte {
	q := msg.Question[0]
	respRawMsg, err := doRequest(ctx, cacheKey(q), rawMsg)
	if err != nil {
		return serverFailure(msg, err, "do request")
	}
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respRawMsg); err != nil {
		return serverFailure(msg, err, "parse upstream dns message")
	}
	respMsg.Id = msg.Id
	respMsg.Question = msg.Question

	storeCache(q, respMsg)

	return packResponse(msg, respMsg, "upstream")
}

func packResponse(msg, respMsg *dns.Msg, source string) []byte {
	respBody, err := respMsg.Pack()
	if err != nil {
		return serverFailure(msg, err, "pack "+source+" dns message")
	}
	if enabledLog {
		slog.Info("answer", "source", source, "q", respMsg.Question, "a", respMsg.Answer)
	}
	return respBody
}

func newReply(msg *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.RecursionAvailable = true
	return reply
}

func serverFailure(msg *dns.Msg, err error, message string) []byte {
	slog.Error(message, "query", msg.Question, "error", err)
	respMsg := new(dns.Msg)
	respMsg.SetRcode(msg, dns.RcodeServerFailure)
	respBody, _ := respMsg.Pack()
	return respBody
}

func doRequest(ctx context.Context, key string, rawMsg []byte) ([]byte, error) {
	result, err, _ := sfGroup.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), upstreamTimeout)
		defer cancel()

		clientConfig := clientConfigs[randomIndex(len(clientConfigs))]
		agents := *userAgents.Load()
		userAgent := agents[randomIndex(len(agents))]

		var errs []error
		for _, dnsConfig := range clientConfig.DNSConfigs {
			respRawMsg, err := fetchUpstream(ctx, clientConfig.Client, dnsConfig.Host, userAgent, rawMsg)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			return respRawMsg, nil
		}

		return nil, fmt.Errorf("all upstream servers failed: %w", errors.Join(errs...))
	})
	if err != nil {
		return nil, err
	}

	respRawMsg, ok := result.([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected upstream result type %T", result)
	}
	return respRawMsg, nil
}

func fetchUpstream(ctx context.Context, client *http.Client, host, userAgent string, rawMsg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host, bytes.NewReader(rawMsg))
	if err != nil {
		return nil, fmt.Errorf("new request %s: %w", host, err)
	}
	req.Header.Set(HeaderContentType, MIMEApplicationDNSMessage)
	req.Header.Set(HeaderAccept, MIMEApplicationDNSMessage)
	req.Header.Set(HeaderUserAgent, userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s: unexpected status %d", host, resp.StatusCode)
	}

	respRawMsg, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("read response %s: %w", host, err)
	}
	return respRawMsg, nil
}

func randomIndex(n int) int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(i.Int64())
}

func echoPOST(c *echo.Context) error {
	if enabledLog {
		slog.Info("request header", "headers", c.Request().Header)
	}

	if c.Request().Header.Get(HeaderContentType) != MIMEApplicationDNSMessage {
		return c.NoContent(http.StatusUnsupportedMediaType)
	}
	rawMsg, err := io.ReadAll(io.LimitReader(c.Request().Body, dns.MaxMsgSize+1))
	if err != nil || len(rawMsg) == 0 || len(rawMsg) > dns.MaxMsgSize {
		return c.NoContent(http.StatusBadRequest)
	}

	return writeDNSResponse(c, rawMsg)
}

func echoGET(c *echo.Context) error {
	rawMsg, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.QueryParam("dns"), "="))
	if err != nil || len(rawMsg) == 0 {
		return c.NoContent(http.StatusBadRequest)
	}

	return writeDNSResponse(c, rawMsg)
}

func writeDNSResponse(c *echo.Context, rawMsg []byte) error {
	respBody, err := resolve(c.Request().Context(), rawMsg)
	if err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
}

func evictDNSCache(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dnsCache.Range(func(key, val any) bool {
				cacheRR, ok := val.([]DNSCacheRR)
				if !ok || slices.ContainsFunc(cacheRR, isExpired) {
					dnsCache.Delete(key)
				}
				return true
			})
		}
	}
}

func isExpired(rr DNSCacheRR) bool {
	return time.Until(rr.Expiry) <= 0
}

func cacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + dns.Type(q.Qtype).String()
}

func storeCache(q dns.Question, respMsg *dns.Msg) {
	if len(respMsg.Answer) == 0 {
		return
	}
	now := time.Now()
	cacheRR := make([]DNSCacheRR, 0, len(respMsg.Answer))
	for _, a := range respMsg.Answer {
		cacheRR = append(cacheRR, DNSCacheRR{
			RR:     dns.Copy(a),
			Expiry: now.Add(time.Duration(a.Header().Ttl) * time.Second),
		})
	}
	dnsCache.Store(cacheKey(q), cacheRR)
}

func getCache(msg *dns.Msg) (*dns.Msg, bool) {
	val, hit := dnsCache.Load(cacheKey(msg.Question[0]))
	if !hit {
		return nil, false
	}
	cacheRR, ok := val.([]DNSCacheRR)
	if !ok || len(cacheRR) == 0 {
		return nil, false
	}

	newMsg := newReply(msg)
	for _, rr := range cacheRR {
		ttl := time.Until(rr.Expiry)
		if ttl <= 0 {
			return nil, false
		}
		cached := dns.Copy(rr.RR)
		cached.Header().Ttl = max(uint32(ttl.Seconds()), 1)
		newMsg.Answer = append(newMsg.Answer, cached)
	}

	return newMsg, true
}

func answerBlocklist(msg *dns.Msg) (*dns.Msg, bool) {
	q := msg.Question[0]
	if !blockList.Load().Match(q.Name) {
		return nil, false
	}

	newMsg := newReply(msg)
	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	switch q.Qtype {
	case dns.TypeA:
		newMsg.Answer = append(newMsg.Answer, &dns.A{Hdr: hdr, A: net.IPv4zero})
	case dns.TypeAAAA:
		newMsg.Answer = append(newMsg.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero})
	}

	return newMsg, true
}

func enableHTTPLog(e *echo.Echo) {
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError:      true,
		LogLatency:       true,
		LogProtocol:      true,
		LogMethod:        true,
		LogURI:           true,
		LogRoutePath:     true,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			attrs := make([]slog.Attr, 0, 7)
			attrs = append(attrs,
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("bytes_in", v.ContentLength),
				slog.Int64("bytes_out", v.ResponseSize),
			)
			if v.Error == nil {
				c.Logger().LogAttrs(c.Request().Context(), slog.LevelInfo, "request", attrs...)
				return nil
			}

			attrs = append(attrs, slog.String("error", v.Error.Error()))
			c.Logger().LogAttrs(c.Request().Context(), slog.LevelError, "request error", attrs...)
			return nil
		},
	}))
}

func listenUDP(address string) (*net.UDPConn, error) {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse udp addr port: %w", err)
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addrPort))
	if err != nil {
		return nil, fmt.Errorf("listen udp server: %w", err)
	}
	return conn, nil
}

func serveUDP(conn *net.UDPConn) {
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go handleUDP(conn, remoteAddr, bytes.Clone(buf[:n]))
	}
}

func handleUDP(conn *net.UDPConn, remoteAddr netip.AddrPort, rawMsg []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		slog.Error("unpack udp query", "error", err)
		return
	}

	respBody := truncateUDP(msg, answer(context.Background(), msg, rawMsg))
	if _, err := conn.WriteToUDPAddrPort(respBody, remoteAddr); err != nil {
		slog.Error("write udp", "error", err)
	}
}

func truncateUDP(msg *dns.Msg, respBody []byte) []byte {
	size := dns.MinMsgSize
	if opt := msg.IsEdns0(); opt != nil {
		size = max(int(opt.UDPSize()), dns.MinMsgSize)
	}
	if len(respBody) <= size {
		return respBody
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBody); err != nil {
		return serverFailure(msg, err, "unpack udp response")
	}
	respMsg.Truncate(size)
	truncated, err := respMsg.Pack()
	if err != nil {
		return serverFailure(msg, err, "pack truncated udp response")
	}
	return truncated
}

type Trie struct {
	children map[string]*Trie
	matched  bool
}

func NewTrie() *Trie {
	return &Trie{children: make(map[string]*Trie)}
}

func (t *Trie) Insert(domain string) {
	node := t
	for _, part := range slices.Backward(strings.Split(strings.ToLower(domain), ".")) {
		next, ok := node.children[part]
		if !ok {
			next = NewTrie()
			node.children[part] = next
		}
		node = next
	}
	node.matched = true
}

func (t *Trie) Match(domain string) bool {
	if t == nil {
		return false
	}
	node := t
	for _, part := range slices.Backward(strings.Split(strings.ToLower(domain), ".")) {
		if node.matched {
			return true
		}
		next, ok := node.children[part]
		if !ok {
			return false
		}
		node = next
	}
	return node.matched
}

type DNSConfig struct {
	ID   int
	Host string
	Type Type
}

type Config struct {
	Host string
	Type Type
}

type ClientConfig struct {
	Client     *http.Client `json:"-"`
	DNSConfigs []DNSConfig
}

type Type int

const (
	TypeDefault Type = iota
	TypeTor
)

const (
	TorPrefix   = "tor;"
	OnionSuffix = ".onion"
)

const (
	HeaderAccept              = "Accept"
	HeaderContentType         = "Content-Type"
	HeaderUserAgent           = "User-Agent"
	MIMEApplicationDNSMessage = "application/dns-message"
)
