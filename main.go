package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

var (
	noProxyServers     bool
	httpMode           bool
	blocklistFile      string
	skipListFile       string
	certFile, keyFile  string
	udpAddr            string
	dnsServers         []DNSConfig
	proxyServers       []Config
	enabledLog         bool
	addr               = "127.0.0.1:9553"
	defaultDNSResolver = "host.docker.internal:53"
	defaultDNSServers  = []DNSConfig{
		{0, "https://dns.quad9.net/dns-query", TypeDefault},
		{1, "https://all.dns.mullvad.net/dns-query", TypeDefault},
		{2, "https://security.cloudflare-dns.com/dns-query", TypeDefault},
	}
	defaultProxyServers = []Config{
		{"127.0.0.1:9050", TypeDefault},
	}
)

var (
	hasBlocklist  bool
	hasSkipList   bool
	blockList     = NewTrie()
	skipList      = NewTrie()
	clientConfigs = make([]ClientConfig, 0)
)

var dnsCache = new(sync.Map)

type DNSCacheRR struct {
	RR     dns.RR
	Expiry time.Time
}

func parseFlags() {
	flag.BoolVar(&httpMode, "http", httpMode, "set http mode")
	flag.StringVar(&addr, "addr", addr, "set address")
	flag.StringVar(&udpAddr, "udp", "", "set udp address")
	flag.StringVar(&certFile, "cert", "", "set cert.pem file")
	flag.StringVar(&keyFile, "key", "", "set key.pem file")
	flag.StringVar(&skipListFile, "skiplist", "", "set skip list file")
	flag.StringVar(&blocklistFile, "blocklist", "", "set blocklist file")
	flag.StringVar(&defaultDNSResolver, "default-resolver", defaultDNSResolver, "set default dns server")
	flag.BoolVar(&enabledLog, "log", enabledLog, "enable log")
	flag.Func("proxy", "set proxy servers to query dns using random routes", func(s string) error {
		if noProxyServers {
			return nil
		}
		if len(s) == 0 {
			return errors.New("proxy server cannot be empty")
		}
		if s == "off" {
			noProxyServers = true
			proxyServers = make([]Config, 0)
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
	flag.Func("dns", "set doh dns server", func(s string) error {
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
	flag.Parse()

	if len(dnsServers) == 0 {
		dnsServers = defaultDNSServers
	}
	slices.SortFunc(dnsServers, func(a, b DNSConfig) int {
		return a.ID - b.ID
	})
	if !noProxyServers && len(proxyServers) == 0 {
		proxyServers = defaultProxyServers
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	parseFlags()

	if !httpMode && (len(certFile) == 0 || len(keyFile) == 0) {
		slog.Error("empty keys file path", "error", "empty keys")
		os.Exit(1)
		return
	}

	if err := readSkipList(skipListFile); err != nil {
		slog.Error("read skip list", "error", err)
		os.Exit(1)
		return
	}
	hasSkipList = skipList.IsZero()

	if err := readBlocklist(blocklistFile); err != nil {
		slog.Error("read blocklist", "error", err)
		os.Exit(1)
		return
	}
	hasBlocklist = blockList.IsZero()

	// enable udp server if enabled
	if len(udpAddr) > 0 {
		go StartUDPServer()
	}

	// setup http client
	proxyLen := len(proxyServers)
	clientConfigs = make([]ClientConfig, proxyLen)
	if !noProxyServers {
		for i, proxyServer := range proxyServers {
			dial, err := proxy.SOCKS5("tcp", proxyServer.Host, nil, proxy.Direct)
			if err != nil {
				slog.Error("connect to proxy server", "error", err)
				os.Exit(1)
				return
			}
			dialer := dial.(proxy.ContextDialer)
			dnsConfigs := slices.Clone(dnsServers)
			if proxyServer.Type == TypeDefault {
				dnsConfigs = slices.DeleteFunc(dnsConfigs, func(d DNSConfig) bool {
					return d.Type == TypeTor
				})
			}
			httpTransport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			}
			http2.ConfigureTransport(httpTransport)

			clientConfigs[i] = ClientConfig{
				DNSConfigs: dnsConfigs,
				Client: &http.Client{
					Transport: httpTransport,
					Timeout:   30 * time.Second,
				},
			}
		}
	} else {
		// remove dns over tor because no proxy
		dnsServers = slices.DeleteFunc(dnsServers, func(d DNSConfig) bool {
			return d.Type == TypeTor
		})
		httpTransport := http.DefaultTransport.(*http.Transport)
		http2.ConfigureTransport(httpTransport)
		clientConfigs = append(clientConfigs, ClientConfig{
			DNSConfigs: dnsServers,
			Client: &http.Client{
				Transport: httpTransport,
			},
		})
	}

	if enabledLog {
		slog.Info("print proxy servers", "servers", proxyServers)
		slog.Info("print dns servers", "servers", dnsServers)
		slog.Info("print client configs", "clients", clientConfigs)
	}

	// clear dns cache
	go evictDNSCache()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// start http server
	go func() {
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

		startFn := sc.StartTLS
		if httpMode {
			// wrap start tls
			startFn = func(ctx context.Context, h http.Handler, _, _ any) error {
				return sc.Start(ctx, h)
			}
		}
		if err := startFn(ctx, e, certFile, keyFile); err != nil {
			e.Logger.Error("start server", "error", err)
		}
	}()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

type StartFn = func(context.Context, http.Handler, string, string) error

func query(c *echo.Context, rawMsg []byte) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return newError(c, msg, err, "invalid query message")
	}

	if enabledLog {
		slog.Info("query", "q", msg.Question)
	}

	if hasSkipList {
		for _, q := range msg.Question {
			if skipList.Match(q.Name) {
				rawBody, err := resolveSkipUDP(c.Request().Context(), rawMsg)
				if err != nil {
					return newError(c, msg, err, "skip domain")
				}
				return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, rawBody)
			}
		}
	}

	// allow only type: A and CNAME
	if len(msg.Question) > 0 && (msg.Question[0].Qtype != dns.TypeA && msg.Question[0].Qtype != dns.TypeCNAME) {
		newMsg := new(dns.Msg)
		newMsg.SetReply(msg)
		respBody, _ := newMsg.Pack()
		return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
	}

	// get cache
	if msg, hit := getCache(msg); hit {
		respBody, err := msg.Pack()
		if err != nil {
			return newError(c, msg, err, "hit cache")
		}
		return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
	}

	// skip if blocklist is empty
	if hasBlocklist {
		if msg, isBlock := answerBlocklist(msg); isBlock {
			respBody, err := msg.Pack()
			if err != nil {
				return newError(c, msg, err, "block domain")
			}
			return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
		}
	}

	// query from upstream servers
	resp, err := doRequest(c.Request().Context(), rawMsg)
	if err != nil {
		return newError(c, msg, err, "do request")
	}
	defer resp.Body.Close()

	// parse response body
	respRawMsg, err := io.ReadAll(resp.Body)
	if err != nil {
		return newError(c, msg, err, "read response message")
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respRawMsg); err != nil {
		return newError(c, msg, err, "parse dns message")
	}

	if len(respMsg.Answer) > 0 {
		// cache dns RR header
		for _, a := range respMsg.Answer {
			key := a.Header().Name + dns.Type(a.Header().Rrtype).String()
			dnsCache.Store(key, DNSCacheRR{
				RR:     dns.Copy(a),
				Expiry: time.Now().Add(time.Duration(a.Header().Ttl) * time.Second),
			})
		}
	}

	respBody, err := respMsg.Pack()
	if err != nil {
		return newError(c, msg, err, "pack dns message")
	}
	return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
}

func resolveSkipUDP(ctx context.Context, rawMsg []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", defaultDNSResolver)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	n, err := conn.Write(rawMsg)
	if err != nil || n == 0 {
		if n == 0 {
			err = io.EOF
		}
		return nil, fmt.Errorf("write msg udp: %w", err)
	}

	buf := make([]byte, 4096)
	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		if n == 0 {
			err = io.EOF
		}
		return nil, fmt.Errorf("read msg udp: %w", err)
	}
	return buf[:n], nil
}

func doRequest(ctx context.Context, rawMsg []byte) (*http.Response, error) {
	idx := rand.IntN(len(clientConfigs))

	for _, dnsConfig := range clientConfigs[idx].DNSConfigs {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, dnsConfig.Host, bytes.NewReader(rawMsg))
		if err != nil {
			continue
		}
		req.ContentLength = int64(len(rawMsg))
		req.Header.Set(echo.HeaderContentType, MIMEApplicationDNSMessage)
		req.Header.Set(echo.HeaderAccept, MIMEApplicationDNSMessage)

		resp, err := clientConfigs[idx].Client.Do(req)
		if err != nil {
			continue
		}
		return resp, nil
	}

	return nil, errors.New("all upstream servers failed")
}

func echoPOST(c *echo.Context) error {
	contentType := c.Request().Header.Get(echo.HeaderContentType)
	if contentType != MIMEApplicationDNSMessage {
		return newError(c, nil, nil, "query message not found")
	}
	rawMsg, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return newError(c, nil, nil, "query message not found")
	}

	return query(c, rawMsg)
}

func echoGET(c *echo.Context) error {
	domainName := c.QueryParam("dns")
	if len(domainName) == 0 {
		return newError(c, nil, nil, "query message not found")
	}
	rawMsg, err := base64.RawStdEncoding.DecodeString(domainName)
	if err != nil {
		return newError(c, nil, nil, "query message not found")
	}

	return query(c, rawMsg)
}

func newError(c *echo.Context, msg *dns.Msg, err error, message string) error {
	var respBody []byte
	if msg != nil {
		newMsg := new(dns.Msg)
		newMsg.SetRcode(msg, dns.RcodeServerFailure)
		respBody, _ = newMsg.Pack()
		c.Logger().ErrorContext(
			c.Request().Context(),
			message,
			"query", msg.Question,
			"error", err,
		)
	}
	return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
}

func evictDNSCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	cleanFn := func() {
		dnsCache.Range(func(key any, val any) bool {
			rr := val.(DNSCacheRR)
			ttl := time.Until(rr.Expiry).Seconds()
			if ttl <= 0 {
				dnsCache.Delete(key)
			}
			return true
		})
	}

	for range ticker.C {
		cleanFn()
	}
}

func getCache(msg *dns.Msg) (*dns.Msg, bool) {
	newMsg := new(dns.Msg)
	newMsg.SetReply(msg)

	for _, q := range msg.Question {
		key := q.Name + dns.Type(q.Qtype).String()
		val, hit := dnsCache.Load(key)
		if !hit {
			continue
		}
		cache := val.(DNSCacheRR)
		ttl := time.Until(cache.Expiry).Seconds()
		if ttl <= 0 {
			continue
		}
		rr := dns.Copy(cache.RR)
		rr.Header().Ttl = uint32(ttl)
		if ttl == 0 {
			rr.Header().Ttl = 1
		}

		newMsg.Answer = append(newMsg.Answer, rr)
	}

	if len(newMsg.Answer) == 0 {
		return msg, false
	}
	return newMsg, true
}

func answerBlocklist(msg *dns.Msg) (*dns.Msg, bool) {
	for _, q := range msg.Question {
		if blockList.Match(q.Name) {
			newMsg := new(dns.Msg)
			newMsg.SetReply(msg)
			newMsg.Answer = append(newMsg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4zero,
			})

			return newMsg, true
		}
	}

	return msg, false
}

func readConfigFile(filename string, trieList *Trie) error {
	if len(filename) == 0 {
		return nil
	}
	fs, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open %s filename: %w", filename, err)
	}
	defer fs.Close()

	var line string
	for {
		if _, err := fmt.Fscanln(fs, &line); err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if !strings.HasSuffix(line, ".") {
			line += "."
		}
		trieList.Insert(line)
	}

	return nil
}

func readBlocklist(blocklistFile string) error {
	return readConfigFile(blocklistFile, blockList)
}

func readSkipList(skipListFile string) error {
	return readConfigFile(skipListFile, skipList)
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
			logger := c.Logger()
			if v.Error == nil {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "request",
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
					slog.String("bytes_in", v.ContentLength),
					slog.Int64("bytes_out", v.ResponseSize),
				)
				return nil
			}

			logger.LogAttrs(context.Background(), slog.LevelError, "request error",
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("bytes_in", v.ContentLength),
				slog.Int64("bytes_out", v.ResponseSize),
				slog.String("error", v.Error.Error()),
			)
			return nil
		},
	}))
}

func StartUDPServer() {
	addrPort, err := netip.ParseAddrPort(udpAddr)
	if err != nil {
		slog.Error("parse udp addr port", "error", err)
		os.Exit(1)
		return
	}

	addr := net.UDPAddrFromAddrPort(addrPort)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		slog.Error("listen udp server", "error", err)
		os.Exit(1)
		return
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go handleUDP(conn, remoteAddr, buf[:n])
	}
}

func handleUDP(conn *net.UDPConn, addr *net.UDPAddr, rawMsg []byte) {
	req, _ := http.NewRequest("POST", "/dns-query", bytes.NewReader(rawMsg))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	c := echo.NewContext(req, rec)

	if err := query(c, rawMsg); err != nil {
		return
	}

	conn.WriteToUDP(rec.Body.Bytes(), addr)
}

type Trie struct {
	children map[string]*Trie
	matched  bool
}

func NewTrie() *Trie {
	return &Trie{children: map[string]*Trie{}}
}

func (t *Trie) IsZero() bool {
	return len(t.children) == 0
}

func (t *Trie) Insert(domain string) {
	parts := strings.Split(domain, ".")
	node := t
	for i := len(parts) - 1; i >= 0; i-- {
		if node.children[parts[i]] == nil {
			node.children[parts[i]] = &Trie{children: map[string]*Trie{}}
		}
		node = node.children[parts[i]]
	}
	node.matched = true
}

func (t *Trie) Match(domain string) bool {
	parts := strings.Split(domain, ".")
	node := t
	for i := len(parts) - 1; i >= 0; i-- {
		if node.matched {
			return true
		}
		next, ok := node.children[parts[i]]
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
	Client     *http.Client
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

const MIMEApplicationDNSMessage = "application/dns-message"
