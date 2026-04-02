FROM docker.io/golang:1.26-alpine3.23 as builder

WORKDIR /builder
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build --ldflags="-w -s" -o main .

FROM docker.io/alpine:3.23

WORKDIR /opt/doh
COPY --from=builder /builder/main server
RUN chown nobody:nobody server

USER nobody
ENTRYPOINT ["/opt/doh/server"]
