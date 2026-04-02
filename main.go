package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

const MIMEApplicationDNSMessage = "application/dns-message"

var (
	blocklistFile     string
	certFile, keyFile string
	addr, dnsServer   string
	proxyServer       string
	enabledLog        bool
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
	flag.StringVar(&addr, "addr", "127.0.0.1:9553", "set address")
	flag.StringVar(&certFile, "cert", "", "set cert.pem file")
	flag.StringVar(&keyFile, "key", "", "set key.pem file")
	flag.StringVar(&proxyServer, "proxy", "127.0.0.1:9050", "set proxy server to query dns")
	flag.StringVar(&dnsServer, "dns", "https://dns.quad9.net/dns-query", "set doh dns server")
	flag.StringVar(&blocklistFile, "blocklist", "", "set blocklist file")
	flag.BoolVar(&enabledLog, "log", false, "enable log")
	flag.Parse()

	e := echo.New()
	if len(certFile) == 0 || len(dnsServer) == 0 {
		e.Logger.Error("empty keys file path", "error", "empty keys")
		os.Exit(1)
		return
	}

	if err := readBlocklist(blocklistFile); err != nil {
		e.Logger.Error("read blocklist", "error", err)
		os.Exit(1)
		return
	}
	hasBlocklist = len(blockList) > 0

	// setup http client
	dial, err := proxy.SOCKS5("tcp", proxyServer, nil, proxy.Direct)
	if err != nil {
		e.Logger.Error("connect to proxy server", "error", err)
		os.Exit(1)
		return
	}
	client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial.Dial(network, addr)
			},
			ForceAttemptHTTP2: true,
		},
	}

	e.Use(middleware.Recover())
	if enabledLog {
		e.Use(middleware.RequestLogger())
	}

	g := e.Group("dns-query")
	g.POST("", echoPOST)
	g.GET("", echoGET)

	sc := echo.StartConfig{Address: addr}
	if err := sc.StartTLS(context.Background(), e, certFile, keyFile); err != nil {
		e.Logger.Error("start server", "error", err)
	}
}

func query(c *echo.Context, rawMsg []byte) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid query message").Wrap(err)
	}

	// get cache
	if msg, hit := getCache(msg); hit {
		respBody, err := msg.Pack()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "hit cache").Wrap(err)
		}
		return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
	}

	// skip if blocklist is empty
	if hasBlocklist {
		if msg, isBlock := answerBlocklist(msg); isBlock {
			respBody, err := msg.Pack()
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "block domain").Wrap(err)
			}
			return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
		}
	}

	// query into server
	req, err := http.NewRequest(http.MethodPost, dnsServer, bytes.NewReader(rawMsg))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "new http request").Wrap(err)
	}
	req.Header.Set(echo.HeaderContentType, MIMEApplicationDNSMessage)
	req.Header.Set(echo.HeaderAccept, MIMEApplicationDNSMessage)
	httpResp, err := client.Do(req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "do request").Wrap(err)
	}
	defer httpResp.Body.Close()

	// parse response body
	rawMsg, err = io.ReadAll(httpResp.Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "read response message").Wrap(err)
	}
	msg = new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "parse dns message").Wrap(err)
	}

	// cache dns RR header
	dnsCacheMutex.Lock()
	for _, a := range msg.Answer {
		key := a.Header().Name + dns.Type(a.Header().Rrtype).String()
		dnsCache[key] = DNSCacheRR{
			RR:     dns.Copy(a.Header()),
			Expiry: time.Now().Add(time.Duration(a.Header().Ttl) * time.Second),
		}
	}
	dnsCacheMutex.Unlock()

	respBody, err := msg.Pack()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "pack dns message").Wrap(err)
	}
	return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
}

func echoPOST(c *echo.Context) error {
	contentType := c.Request().Header.Get(echo.HeaderContentType)
	if contentType != MIMEApplicationDNSMessage {
		return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
	}
	rawMsg, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
	}

	return query(c, rawMsg)
}

func echoGET(c *echo.Context) error {
	domainName := c.QueryParam("dns")
	if len(domainName) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
	}
	rawMsg, err := base64.RawStdEncoding.DecodeString(domainName)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid query message").Wrap(err)
	}

	return query(c, rawMsg)
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
		if ttl < 0 {
			continue
		}
		rr := dns.Copy(cache.RR)
		rr.Header().Ttl = uint32(ttl)

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
				A: blockIP,
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
