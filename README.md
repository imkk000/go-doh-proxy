# Play DOH

DNS-over-HTTPS (DoH) proxy server over Tor. Implements [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484).

## Design

```
client → local doh server → torsocks → upstream doh → answer
```

## Usage

```bash
# Build
task build

# Generate TLS cert
task gen_cert DOMAIN=<your domain>

# Run
go run . \
  --addr=127.0.0.1:9553 \
  --cert=fullchains1.pem \
  --key=privkey1.pem \
  --proxy=127.0.0.1:9050 \
  --dns=https://dns.quad9.net/dns-query \
  --dns=https://security.cloudflare-dns.com/dns-query \
  --blocklist=blocklist.txt \
  --log
```

## Options

| Flag          | Description                                        |
| ------------- | -------------------------------------------------- |
| `--addr`      | Listen address                                     |
| `--cert`      | TLS certificate                                    |
| `--key`       | TLS private key                                    |
| `--proxy`     | SOCKS5 proxy                                       |
| `--dns`       | Upstream DoH server (support multiple dns)         |
| `--blocklist` | Blocklist file, one domain per line (suffix match) |
| `--log`       | Enable request log                                 |

## Notes

- Allow only type: `[A, CNAME]`
- Blocked domains return `0.0.0.0` (type A)
- TCP mode: use `proxychains` as alternative to torsocks
