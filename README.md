# Play DOH

## Why?

I try to implement follow doh [rfc8484](https://datatracker.ietf.org/doc/html/rfc8484).
I want to run doh over tor with my custom doh server.

## Design

```
client -> local doh server -> torsocks -> dial tcp dns server -> answer
```

## CLI

```bash
# generate letencrypt with certbot manually
task gen_cert DOMAIN=<public domain>

# server hostname (if build change to :9553)
--addr=127.0.0.1:9553

# tls cert and key
--cert=fullchains1.pem
--key=privkey1.pem

# exchange dns server
--dns=127.0.0.1:9059
# for tor inside docker I use and link dns server in same network
--dns=onion_dns:9053

# blocklist file and insert domain per line (e.g. www.google.com.)
--blocklist=blocklist.txt
```

## Notes

- Drop blacklist using `0.0.0.0` instead of `127.0.0.1`
- Can use `proxychains` to query dns when set dns client to **TCP**
