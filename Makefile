.PHONY: all build doubletake doubletake-ctl doubletake-test-receiver doubletake-release doubletake-ctl-release doubletake-test-receiver-release manpages-release install install-man install-systemd uninstall test clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user

all: doubletake doubletake-ctl doubletake-test-receiver

build: all

doubletake:
	go build -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

doubletake-test-receiver:
	go build -o bin/doubletake-test-receiver ./cmd/doubletake-test-receiver

doubletake-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake-ctl ./cmd/doubletake-ctl

doubletake-test-receiver-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake-test-receiver ./cmd/doubletake-test-receiver

manpages-release:
	tar -czf doubletake-manpages.tar.gz -C man man1

test:
	go test ./...

install: all install-man install-systemd
	install -m 755 bin/doubletake $(PREFIX)/bin/
	install -m 755 bin/doubletake-ctl $(PREFIX)/bin/
	install -m 755 bin/doubletake-test-receiver $(PREFIX)/bin/

install-man:
	install -d $(MANDIR)/man1
	install -m 644 man/man1/doubletake.1 $(MANDIR)/man1/
	install -m 644 man/man1/doubletake-ctl.1 $(MANDIR)/man1/
	install -m 644 man/man1/doubletake-test-receiver.1 $(MANDIR)/man1/

install-systemd:
	mkdir -p bin
	sed 's|@bindir@|$(PREFIX)/bin|' systemd/doubletake.service.in > bin/doubletake.service
	install -d $(SYSTEMDUSERDIR)
	install -m 644 bin/doubletake.service $(SYSTEMDUSERDIR)/

uninstall:
	rm -f $(PREFIX)/bin/doubletake
	rm -f $(PREFIX)/bin/doubletake-ctl
	rm -f $(PREFIX)/bin/doubletake-test-receiver
	rm -f $(MANDIR)/man1/doubletake.1
	rm -f $(MANDIR)/man1/doubletake-ctl.1
	rm -f $(MANDIR)/man1/doubletake-test-receiver.1
	rm -f $(SYSTEMDUSERDIR)/doubletake.service

clean:
	rm -rf bin/
	go clean -testcache
