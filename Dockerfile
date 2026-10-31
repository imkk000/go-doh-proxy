FROM docker.io/golang:1.27-alpine3.24 as builder

WORKDIR /builder
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build --ldflags="-w -s" -o main .

FROM docker.io/alpine:3.24

WORKDIR /opt/doh
COPY --from=builder /builder/main server
RUN chown nobody:nobody server

USER nobody
ENTRYPOINT ["/opt/doh/server"]
