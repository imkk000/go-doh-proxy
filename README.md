# Play DOH

DNS-over-HTTPS (DoH) proxy server over Tor. Implements [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484).

## Why Tor / `.onion`?

Normally, even with DoH, your DNS queries travel over the internet with your real IP attached — the upstream resolver knows who is asking. Tor solves this by routing traffic through a chain of encrypted relays: your request enters the network at one point and exits at another, with no single node knowing both the source and the destination. It is like teleportation — the query disappears from your end and reappears at the upstream DNS server with no traceable path back to you.

`.onion` DNS servers go further: they are hidden services that exist entirely inside the Tor network, so the query never exits to the public internet at all. This eliminates the exit-node hop as a potential observer.

## Design

```
client → local doh server → SOCKS5 proxy (random) → upstream doh → answer
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
  --udp=127.0.0.1:9053 \
  --cert=fullchains1.pem \
  --key=privkey1.pem \
  --proxy=127.0.0.1:9050 \
  --proxy=127.0.0.1:9051 \
  --proxy=127.0.0.1:9052 \
  --proxy=tor;127.0.0.1:9052 \
  --dns=-1;http://tor.onion/dns-query \
  --dns=0;https://dns.quad9.net/dns-query \
  --dns=1;https://security.cloudflare-dns.com/dns-query \
  --blocklist=blocklist.txt \
  --default-resolver=127.0.0.1:53 \
  --ua=useragents.txt \
  --http \
  --log
```

## Options

| Flag                 | Default                      | Description                                                                                          |
| -------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| `--http`             | `false`                      | Run server with HTTP instead of HTTPS (skips cert/key requirement)                                   |
| `--addr`             | `127.0.0.1:9553`             | HTTPS/HTTP listen address                                                                            |
| `--udp`              | _(disabled)_                 | UDP listen address; omit to disable UDP server                                                       |
| `--cert`             |                              | TLS certificate file (required unless `--http`)                                                      |
| `--key`              |                              | TLS private key file (required unless `--http`)                                                      |
| `--proxy`            | _(none)_                     | SOCKS5 proxy; use `off` for direct connection; prefix `tor;` for Tor-only routing; supports multiple |
| `--dns`              | quad9, mullvad, cloudflare   | Upstream DoH server in `<index>;<url>` format; lower index = higher priority; supports multiple      |
| `--ua`               | _(built-in browser UA list)_ | Path to a file of User-Agent strings (one per line) sent to upstream DoH servers                     |
| `--skiplist`         |                              | Skip list file, one domain per line; matched domains bypass DoH and resolve via UDP                  |
| `--default-resolver` | `host.docker.internal:53`    | UDP resolver used for skip list domains                                                              |
| `--blocklist`        |                              | Blocklist file, one domain per line (suffix match)                                                   |
| `--log`              | `false`                      | Enable request logging                                                                               |

## API

Implements [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) DNS-over-HTTPS.

### `POST /dns-query`

Send a DNS query in wire format.

| Item         | Value                     |
| ------------ | ------------------------- |
| Content-Type | `application/dns-message` |
| Accept       | `application/dns-message` |
| Body         | DNS wire-format message   |
| Response 200 | DNS wire-format message   |

```bash
curl -s \
  -X POST \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @query.bin \
  https://127.0.0.1:9553/dns-query
```

### `GET /dns-query?dns=<message>`

Send a DNS query encoded as base64url (no padding) in the `dns` query parameter.

| Item         | Value                                          |
| ------------ | ---------------------------------------------- |
| Query param  | `dns` — base64url (no padding) encoded message |
| Accept       | `application/dns-message`                      |
| Response 200 | DNS wire-format message                        |

```bash
curl -s \
  -H "Accept: application/dns-message" \
  "https://127.0.0.1:9553/dns-query?dns=<base64url>"
```

> Only query types `A`, `AAAA`, `CNAME`, `SRV`, and `TXT` are forwarded upstream. All other types receive an empty reply.

## Notes

- Send `SIGHUP` to reload `--skiplist`, `--blocklist`, and `--ua` files without restarting
- Only DNS query types `A`, `AAAA`, `CNAME`, `SRV`, and `TXT` are resolved; others return an empty reply
- Blocked domains return `0.0.0.0` for type A or `::` for type AAAA (TTL 300); the blocklist is checked before the cache, so a reloaded blocklist applies immediately
- Positive responses are cached in-memory by their minimum answer TTL, capped at 7 days; TTLs with the high bit set are treated as 0 and not cached
- Negative responses (NXDOMAIN, and NODATA including a CNAME chain without the requested type) are cached only with an SOA, for the SOA minimum TTL capped at 1 hour
- The cache holds at most 100,000 entries; every 10 minutes entries more than 24h past expiry are evicted, and all expired entries are evicted while the cache is full
- Serve-stale (RFC 8767): an entry expired by less than 24h triggers a refresh; if the refresh errors, returns an rcode other than NOERROR/NXDOMAIN, or takes longer than 1.8s, the stale answer is returned with TTL 30; after a failed refresh, stale answers are returned immediately for 30s before refreshing again
- Upstream queries are rebuilt from the question only: message ID 0, only RD set, no client EDNS options (ECS, cookies, DO/CD), and EDNS padding to 128-byte blocks; clients get a fresh OPT record only if they sent one
- Concurrent identical queries are deduplicated via singleflight — only one upstream request is made
- Upstream requests start at a random `--proxy` and fail over across all proxies; within each proxy, `--dns` servers are tried in index order and the first success wins
- Each upstream attempt has a 10s timeout within a 30s total budget; transport errors, non-200 statuses, and unparsable bodies trigger failover, while SERVFAIL and REFUSED are returned as-is
- A (proxy, DNS server) pair that fails 3 times in a row is skipped for 60s (overlapping failures from concurrent requests count once); if every pair is cooling down, they are still tried as a last resort
- `tor;` proxy prefix: that proxy can also route to `.onion` DNS endpoints; regular proxies skip `.onion` DNS servers entirely
- DNS servers with `.onion` hosts are skipped when proxies are disabled (`--proxy=off`)
- Skip list domains bypass DoH entirely and are resolved via plain UDP to `--default-resolver`
- Use `proxychains` as an alternative to a SOCKS5 proxy
