.DEFAULT_GOAL := all

GO ?= go
GOFLAGS ?=
PACKAGES ?= ./...
BINARY ?= httpaudit
BUILD_DIR ?= bin
BUILD_PATH := $(BUILD_DIR)/$(BINARY)

.PHONY: all deps build test test-cover vet check install

all: check build

deps:
	$(GO) mod download
	$(GO) mod verify

build: deps
	mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_PATH) .

test: deps
	$(GO) test $(GOFLAGS) $(PACKAGES)

test-cover: deps
	$(GO) test $(GOFLAGS) -cover $(PACKAGES)

vet: deps
	$(GO) vet $(GOFLAGS) $(PACKAGES)

check: vet test

install: check
	$(GO) install $(GOFLAGS) .
