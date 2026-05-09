.PHONY: all build doubletake doubletake-ctl test clean

all: doubletake doubletake-ctl

build: all

doubletake:
	go build -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

test:
	go test ./...

clean:
	rm -rf bin/
	go clean -testcache
