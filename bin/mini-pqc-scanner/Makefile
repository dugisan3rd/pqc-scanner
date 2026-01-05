# Mini PQC Scanner Build Configuration
#
# Simplified Makefile for the mini PQC Scanner CLI-only version

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=mini-pqc-scanner
MAIN_PATH=./cmd

# Build directory
BUILD_DIR=./bin

# Version files
VERSION_DIR=./version
VERSION_FILE=$(VERSION_DIR)/scanner_version

# Ensure version directory exists
$(shell mkdir -p $(VERSION_DIR))

# Read current version or set default if file doesn't exist
VERSION=$(shell if [ -f $(VERSION_FILE) ]; then cat $(VERSION_FILE); else echo "0.1.0"; fi)

# Build flags with version information
BUILD_FLAGS=-ldflags="-s -w -X 'main.Version=$(VERSION)'"

# Default target
all: deps build

# Build the binary
build:
	@echo "Building Mini PQC Scanner..."
	mkdir -p $(BUILD_DIR)
	@echo "# Store source code hash to detect actual code changes"
	find . -type f -name "*.go" | grep -v "/\." | sort | xargs cat | md5sum > $(BUILD_DIR)/.source.md5.new
	@echo "# Check if source code changed and update version if needed"
	if [ -f $(BUILD_DIR)/.source.md5.old ] && diff -q $(BUILD_DIR)/.source.md5.old $(BUILD_DIR)/.source.md5.new > /dev/null; then \
		echo "No code changes detected, using existing version: $(VERSION)"; \
	else \
		if [ -f $(BUILD_DIR)/.source.md5.old ]; then \
			echo "Code changes detected, incrementing version"; \
			awk -F. '{$$NF = $$NF + 1;} 1' OFS=. $(VERSION_FILE) > $(VERSION_FILE).new; \
			mv $(VERSION_FILE).new $(VERSION_FILE); \
		else \
			echo "First build or after clean, using existing version or creating initial version"; \
			if [ ! -f $(VERSION_FILE) ]; then \
				echo "0.1.0" > $(VERSION_FILE); \
			fi; \
		fi; \
		echo "Using version: $$(cat $(VERSION_FILE))"; \
	fi
	@echo "# Build the binary with current version"
	@VERSION=$$(cat $(VERSION_FILE)) && echo "Building with version: $$VERSION" && \
	go build -ldflags="-s -w -X 'main.Version=$$VERSION'" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "# Save current source hash for next comparison"
	mv $(BUILD_DIR)/.source.md5.new $(BUILD_DIR)/.source.md5.old
	@echo "Build complete. Binary available at: $(BUILD_DIR)/$(BINARY_NAME) (v$$(cat $(VERSION_FILE)))"

# Build for specific platforms
build-linux:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64 $(MAIN_PATH)

build-windows:
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_windows_amd64.exe $(MAIN_PATH)

build-mac:
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_darwin_amd64 $(MAIN_PATH)

# Build all platforms
build-all-platforms: build-linux build-windows build-mac

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run the application
run: build
	$(BUILD_DIR)/$(BINARY_NAME)

# Install to GOPATH/bin
install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Help command
help:
	@echo "Available commands:"
	@echo "  make              - Build the application after fetching dependencies"
	@echo "  make build        - Build the application"
	@echo "  make build-linux  - Build for Linux"
	@echo "  make build-windows- Build for Windows"
	@echo "  make build-mac    - Build for macOS"
	@echo "  make build-all-platforms - Build for all platforms"
	@echo "  make deps         - Download and tidy dependencies"
	@echo "  make test         - Run tests"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make run          - Build and run the application"
	@echo "  make install      - Install to GOPATH/bin"

.PHONY: all build build-linux build-windows build-mac build-all-platforms deps test clean run install help
