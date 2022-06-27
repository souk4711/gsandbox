GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILT_TIME := $(shell date +%s)
LDFLAGS := -X 'main.GitCommit=${GIT_COMMIT}' -X 'main.BuiltTime=${BUILT_TIME}'

.PHONY: default fmt lint test build clean

default: fmt lint test build

fmt:
	gofmt -s -w .

lint:
	golangci-lint run

test:
	go test

build:
	go mod tidy
	go build -ldflags "$(LDFLAGS)" -o ./bin/gsandbox ./cmd/gsandbox/

clean:
	go clean
	rm -f ./bin/gsandbox
