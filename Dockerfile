FROM golang:1.26-alpine AS builder

ARG VERSION=0.1.0

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/kochab-agent \
    ./cmd/kochab-agent

# Scratch for minimal image — binary is fully static
FROM scratch

COPY --from=builder /build/kochab-agent /usr/local/bin/kochab-agent
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/kochab-agent"]
