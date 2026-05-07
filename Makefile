.PHONY: build test lint build-linux build-linux-arm64 checksum cross-compile deb release clean

BINARY_NAME := kochab-agent
VERSION ?= 0.1.0
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
	@cd $(BUILD_DIR) && [ -f $(BINARY_NAME)-arm64 ] && sha256sum $(BINARY_NAME)-arm64 > $(BINARY_NAME)-arm64.sha256 || true
	@echo "Checksums written to $(BUILD_DIR)/"

cross-compile: build-linux build-linux-arm64 checksum
	@echo "Cross-compilation complete"

# Story 2-6 Task 1.1 — build .deb amd64 con Version: line templatizzata da $(VERSION).
# Postcondition: $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_amd64.deb + .sha256 sibling.
deb: build-linux
	@command -v dpkg-deb >/dev/null || { echo "ERROR: dpkg-deb non installato (apt-get install dpkg)"; exit 1; }
	@echo "Building .deb v$(VERSION) ..."
	# Templatizza Version: nel control (backup FUORI da DEBIAN/ per non includerlo nel pkg)
	cp packaging/debian/DEBIAN/control $(BUILD_DIR)/control.orig
	sed -i.bak "s/^Version:.*/Version: $(VERSION)/" packaging/debian/DEBIAN/control
	rm -f packaging/debian/DEBIAN/control.bak
	mkdir -p packaging/debian/usr/local/bin packaging/debian/etc/systemd/system
	cp $(BUILD_DIR)/$(BINARY_NAME) packaging/debian/usr/local/bin/
	cp packaging/kochab-agent.service packaging/debian/etc/systemd/system/
	chmod 755 packaging/debian/DEBIAN/postinst packaging/debian/DEBIAN/postrm packaging/debian/DEBIAN/prerm
	find packaging/debian -name '.gitkeep' -delete || true
	dpkg-deb --build --root-owner-group packaging/debian $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_amd64.deb
	# Ripristina control originale (Version placeholder)
	mv $(BUILD_DIR)/control.orig packaging/debian/DEBIAN/control
	# sha256 sibling per .deb
	cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)_$(VERSION)_amd64.deb > $(BINARY_NAME)_$(VERSION)_amd64.deb.sha256
	@echo ".deb built: $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_amd64.deb"

# Story 2-6 Task 1.1 — full release artifacts (cross-compile + deb).
release: cross-compile deb
	@echo "Release artifacts in $(BUILD_DIR)/:"
	@ls -lh $(BUILD_DIR)/

clean:
	rm -rf $(BUILD_DIR)
	rm -rf packaging/debian/usr packaging/debian/etc
