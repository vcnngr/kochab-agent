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

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/kochab-agent /usr/local/bin/kochab-agent

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/kochab-agent"]
