.PHONY: build test lint cross-compile clean

BINARY_NAME := kochab-agent
VERSION := 0.1.0
BUILD_DIR := bin
LDFLAGS := -s -w -X main.version=$(VERSION)
MAX_BINARY_SIZE := 20971520

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/kochab-agent

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

cross-compile:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/kochab-agent
	@size=$$(stat -f%z $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 2>/dev/null || stat -c%s $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64); \
	if [ "$$size" -gt $(MAX_BINARY_SIZE) ]; then \
		echo "ERROR: Binary too large: $$size bytes (max 20MB)"; exit 1; \
	fi; \
	echo "Binary size: $$size bytes - OK"

clean:
	rm -rf $(BUILD_DIR)
