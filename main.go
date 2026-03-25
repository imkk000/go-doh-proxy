package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/miekg/dns"
)

const MIMEApplicationDNSMessage = "application/dns-message"

var (
	blocklistFile     string
	certFile, keyFile string
	addr, dnsServer   string
)

var (
	blockList    = map[string]struct{}{}
	blockIP      = net.ParseIP("0.0.0.0")
	hasBlocklist = false
)

func main() {
	flag.StringVar(&addr, "addr", "127.0.0.1:9553", "set address")
	flag.StringVar(&certFile, "cert", "", "set cert.pem file")
	flag.StringVar(&keyFile, "key", "", "set key.pem file")
	flag.StringVar(&dnsServer, "dns", "127.0.0.1:9059", "set dns server")
	flag.StringVar(&blocklistFile, "blocklist", "", "set blocklist file")
	flag.Parse()

	e := echo.New()
	if err := readBlocklist(blocklistFile); err != nil {
		e.Logger.Error("read blocklist", "error", err)
		os.Exit(1)
		return
	}
	hasBlocklist = len(blockList) > 0

	e.Use(
		middleware.Recover(),
		middleware.RequestLogger(),
		middleware.RequestID(),
	)
	query := func(c *echo.Context, rawMsg []byte) error {
		msg := new(dns.Msg)
		if err := msg.Unpack(rawMsg); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid query message").Wrap(err)
		}

		// skip if blocklist is empty
		if hasBlocklist {
			msg, err, isBlock := answerBlocklist(msg)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "block domain").Wrap(err)
			}
			if isBlock {
				respBody, err := msg.Pack()
				if err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "block domain").Wrap(err)
				}
				return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
			}
		}

		client := new(dns.Client)
		resp, _, err := client.Exchange(msg, dnsServer)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "exchange failed").Wrap(err)
		}
		for i, rr := range resp.Answer {
			if _, found := blockList[resp.Question[i].Name]; found {
				if a, ok := rr.(*dns.A); ok {
					a.A = blockIP
					resp.Answer[i] = a
				}
			}
		}

		respBody, err := resp.Pack()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "exchange failed").Wrap(err)
		}
		return c.Blob(http.StatusOK, MIMEApplicationDNSMessage, respBody)
	}

	g := e.Group("dns-query")
	g.POST("", func(c *echo.Context) error {
		contentType := c.Request().Header.Get(echo.HeaderContentType)
		if contentType != MIMEApplicationDNSMessage {
			return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
		}
		rawMsg, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
		}

		return query(c, rawMsg)
	})
	g.GET("", func(c *echo.Context) error {
		domainName := c.QueryParam("dns")
		if len(domainName) == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "query message not found")
		}
		rawMsg, err := base64.RawStdEncoding.DecodeString(domainName)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid query message").Wrap(err)
		}

		return query(c, rawMsg)
	})

	sc := echo.StartConfig{Address: addr}
	if err := sc.StartTLS(context.Background(), e, certFile, keyFile); err != nil {
		e.Logger.Error("start server", "error", err)
	}
}

func answerBlocklist(msg *dns.Msg) (*dns.Msg, error, bool) {
	for _, q := range msg.Question {
		if _, found := blockList[q.Name]; found {
			newMsg := new(dns.Msg)
			newMsg.SetReply(msg)
			for _, bq := range msg.Question {
				newMsg.Answer = append(newMsg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   bq.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: blockIP,
				})
			}

			return newMsg, nil, true
		}
	}

	return msg, nil, false
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
		blockList[line] = struct{}{}
	}

	return nil
}
