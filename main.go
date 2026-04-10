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
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const MIMEApplicationDNSMessage = "application/dns-message"

var (
	httpMode          bool
	blocklistFile     string
	certFile, keyFile string
	addr, proxyServer string
	udpAddr           string
	dnsServers        []string
	enabledLog        bool
	defaultDNSServers = []string{
		"https://dns.quad9.net/dns-query",
		"https://all.dns.mullvad.net/dns-query",
		"https://security.cloudflare-dns.com/dns-query",
	}
)

var (
	hasBlocklist bool
	blockList    = make(map[string]struct{})
	blockIP      = net.ParseIP("0.0.0.0")
	client       = http.DefaultClient
)

var (
	dnsCache      = make(map[string]DNSCacheRR)
	dnsCacheMutex = new(sync.RWMutex)
)

type DNSCacheRR struct {
	RR     dns.RR
	Expiry time.Time
}

func main() {
	flag.BoolVar(&httpMode, "http", false, "set http mode")
	flag.StringVar(&addr, "addr", "127.0.0.1:9553", "set address")
	flag.StringVar(&udpAddr, "udp", "", "set udp address")
	flag.StringVar(&certFile, "cert", "", "set cert.pem file")
	flag.StringVar(&keyFile, "key", "", "set key.pem file")
	flag.StringVar(&proxyServer, "proxy", "127.0.0.1:9050", "set proxy server to query dns")
	flag.Func("dns", "set doh dns server", func(s string) error {
		if len(s) == 0 {
			return errors.New("dns server cannot be empty")
		}
		dnsServers = append(dnsServers, s)
		return nil
	})
	flag.StringVar(&blocklistFile, "blocklist", "", "set blocklist file")
	flag.BoolVar(&enabledLog, "log", false, "enable log")
	flag.Parse()

	e := echo.New()
	if !httpMode && (len(certFile) == 0 || len(keyFile) == 0) {
		e.Logger.Error("empty keys file path", "error", "empty keys")
		os.Exit(1)
		return
	}
	if len(dnsServers) == 0 {
		dnsServers = defaultDNSServers
	}

	if err := readBlocklist(blocklistFile); err != nil {
		e.Logger.Error("read blocklist", "error", err)
		os.Exit(1)
		return
	}
	hasBlocklist = len(blockList) > 0

	// enable udp server if enabled
	if len(udpAddr) > 0 {
		addrPort, err := netip.ParseAddrPort(udpAddr)
		if err != nil {
			e.Logger.Error("parse udp addr port", "error", err)
			os.Exit(1)
			return
		}

		addr := net.UDPAddrFromAddrPort(addrPort)
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			e.Logger.Error("listen udp server", "error", err)
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

	// setup http client
	dial, err := proxy.SOCKS5("tcp", proxyServer, nil, proxy.Direct)
	if err != nil {
		e.Logger.Error("connect to proxy server", "error", err)
		os.Exit(1)
		return
	}
	dialer := dial.(proxy.ContextDialer)
	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	http2.ConfigureTransport(httpTransport)
	client = &http.Client{
		Transport: httpTransport,
	}

	if enabledLog {
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

	// clear dns cache
	go evictDNSCache()

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
	if err := startFn(context.Background(), e, certFile, keyFile); err != nil {
		e.Logger.Error("start server", "error", err)
	}
}

type StartFn = func(context.Context, http.Handler, string, string) error

func query(c *echo.Context, rawMsg []byte) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return newError(c, msg, err, "invalid query message")
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
		dnsCacheMutex.Lock()
		for _, a := range respMsg.Answer {
			key := a.Header().Name + dns.Type(a.Header().Rrtype).String()
			dnsCache[key] = DNSCacheRR{
				RR:     dns.Copy(a),
				Expiry: time.Now().Add(time.Duration(a.Header().Ttl) * time.Second),
			}
		}
		dnsCacheMutex.Unlock()
	}

	respBody, err := respMsg.Pack()
	if err != nil {
		return newError(c, msg, err, "pack dns message")
	}
	return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
}

func doRequest(ctx context.Context, rawMsg []byte) (*http.Response, error) {
	for _, server := range dnsServers {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(rawMsg))
		if err != nil {
			continue
		}
		req.ContentLength = int64(len(rawMsg))
		req.Header.Set(echo.HeaderContentType, MIMEApplicationDNSMessage)
		req.Header.Set(echo.HeaderAccept, MIMEApplicationDNSMessage)
		resp, err := client.Do(req)
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
		dnsCacheMutex.Lock()
		defer dnsCacheMutex.Unlock()

		for key, rr := range dnsCache {
			ttl := time.Until(rr.Expiry).Seconds()
			if ttl <= 0 {
				delete(dnsCache, key)
			}
		}
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
		dnsCacheMutex.RLock()
		cache, hit := dnsCache[key]
		dnsCacheMutex.RUnlock()
		if !hit {
			continue
		}
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
		if isBlockDomain(q.Name) {
			newMsg := new(dns.Msg)
			newMsg.SetReply(msg)
			// TODO: remove A and use generate per qtype
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

func isBlockDomain(name string) bool {
	_, found := blockList[name]
	if found {
		return true
	}
	for blockName := range blockList {
		if strings.HasSuffix(name, blockName) {
			return true
		}
	}

	return false
}

func readBlocklist(blocklistFile string) error {
	if len(blocklistFile) == 0 {
		return nil
	}
	fs, err := os.Open(blocklistFile)
	if err != nil {
		return fmt.Errorf("open blocklist file: %w", err)
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
		blockList[line] = struct{}{}
	}

	return nil
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
