NAME := vinbero

#brunch name version
VERSION := $(shell git rev-parse --abbrev-ref HEAD)

PKG_NAME=$(shell basename `pwd`)

LDFLAGS := -ldflags="-s -w  -X \"github.com/takehaya/vinbero/pkg/version.Version=$(VERSION)\" -extldflags \"-static\""
SRCS    := $(shell find . -type f -name '*.go')

P4SRC   := "switch.p4"

.DEFAULT_GOAL := build
build: $(SRCS) gen
	go build $(LDFLAGS) -o ./bin/$(NAME) ./cmd/$(NAME)

.PHONY: run
run:
	go run $(LDFLAGS) ./cmd/$(NAME)

.PHONY: test
test:
	go test -v ./integration

## lint
.PHONY: lint
lint:
	@for pkg in $$(go list ./...): do \
		golint --set_exit_status $$pkg || exit $$?; \
	done

.PHONY: codecheck
codecheck:
	test -z "$(gofmt -s -l . | tee /dev/stderr)"
	go vet ./...

.PHONY: clean
clean:
	rm -rf bin

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/$(NAME)

.PHONY: gen
gen:
	go generate pkg/coreelf/elf.go
