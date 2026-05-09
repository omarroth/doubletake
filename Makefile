.PHONY: all build doubletake doubletake-ctl release-doubletake release-doubletake-ctl test clean

all: doubletake doubletake-ctl

build: all

doubletake:
	go build -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

doubletake-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake-ctl ./cmd/doubletake-ctl

test:
	go test ./...

clean:
	rm -rf bin/
	go clean -testcache
