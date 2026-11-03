FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.buildVersion=$(cat VERSION 2>/dev/null || echo dev) \
              -X main.buildDate=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
              -X main.buildCommit=docker" \
    -o passwordkeeper-server ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/passwordkeeper-server .

EXPOSE 9090

ENTRYPOINT ["/app/passwordkeeper-server"]
CMD ["serve"]
