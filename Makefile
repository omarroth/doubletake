.PHONY: all build doubletake doubletake-ctl doubletake-release doubletake-ctl-release manpages-release install install-man uninstall test clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man

all: doubletake doubletake-ctl

build: all

doubletake:
	go build -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

doubletake-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o bin/doubletake ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o bin/doubletake-ctl ./cmd/doubletake-ctl

manpages-release:
	tar -czf doubletake-manpages.tar.gz -C man man1

test:
	go test ./...

install: all install-man
	install -m 755 bin/doubletake $(PREFIX)/bin/
	install -m 755 bin/doubletake-ctl $(PREFIX)/bin/

install-man:
	install -d $(MANDIR)/man1
	install -m 644 man/man1/doubletake.1 $(MANDIR)/man1/
	install -m 644 man/man1/doubletake-ctl.1 $(MANDIR)/man1/

uninstall:
	rm -f $(PREFIX)/bin/doubletake
	rm -f $(PREFIX)/bin/doubletake-ctl
	rm -f $(MANDIR)/man1/doubletake.1
	rm -f $(MANDIR)/man1/doubletake-ctl.1

clean:
	rm -rf bin/
	go clean -testcache
