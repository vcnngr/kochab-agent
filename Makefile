.PHONY: build test lint build-linux build-linux-arm64 checksum cross-compile clean

BINARY_NAME := kochab-agent
VERSION := 0.1.0
BUILD_DIR := bin
LDFLAGS := -s -w -X main.version=$(VERSION)
MAX_BINARY_SIZE := 15728640

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/kochab-agent

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

build-linux:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/kochab-agent
	@size=$$(stat -f%z $(BUILD_DIR)/$(BINARY_NAME) 2>/dev/null || stat -c%s $(BUILD_DIR)/$(BINARY_NAME)); \
	if [ "$$size" -gt $(MAX_BINARY_SIZE) ]; then \
		echo "ERROR: Binary too large: $$size bytes (max 15MB)"; exit 1; \
	fi; \
	echo "Binary size: $$size bytes - OK"

build-linux-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 ./cmd/kochab-agent

checksum:
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME) > $(BINARY_NAME).sha256
	@echo "Checksum written to $(BUILD_DIR)/$(BINARY_NAME).sha256"

cross-compile: build-linux build-linux-arm64 checksum
	@echo "Cross-compilation complete"

clean:
	rm -rf $(BUILD_DIR)
