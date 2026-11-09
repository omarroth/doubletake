.PHONY: all build doubletake doubletake-ctl doubletake-gstreamer-cgo doubletake-test-receiver doubletake-release doubletake-ctl-release manpages-release install install-bin install-man install-systemd uninstall test clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user

all: doubletake doubletake-ctl

build: all

doubletake:
	go build -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

# Experimental dynamically linked build. Video capture runs libgstreamer in
# process, making live encoder controls and transport-driven rate adjustment
# available without changing the default or release builds.
doubletake-gstreamer-cgo:
	CGO_ENABLED=1 go build -tags gstreamer_cgo -o bin/doubletake-gstreamer-cgo ./cmd/doubletake

# Developer-only diagnostic receiver; build explicitly when needed.
doubletake-test-receiver:
	go build -o bin/doubletake-test-receiver ./cmd/doubletake-test-receiver

doubletake-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -ldflags='-s -w -extldflags=-static' -o doubletake-ctl ./cmd/doubletake-ctl

manpages-release:
	tar -czf doubletake-manpages.tar.gz -C man man1/doubletake.1 man1/doubletake-ctl.1

test:
	go test ./...

install: all install-bin install-man install-systemd

install-bin:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 bin/doubletake $(DESTDIR)$(PREFIX)/bin/
	install -m 755 bin/doubletake-ctl $(DESTDIR)$(PREFIX)/bin/

install-man:
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 man/man1/doubletake.1 $(DESTDIR)$(MANDIR)/man1/
	install -m 644 man/man1/doubletake-ctl.1 $(DESTDIR)$(MANDIR)/man1/

install-systemd:
	install -d bin
	sed 's|@bindir@|$(PREFIX)/bin|g' systemd/doubletake.service.in > bin/doubletake.service
	install -d $(DESTDIR)$(SYSTEMDUSERDIR)
	install -m 644 bin/doubletake.service $(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/doubletake
	rm -f $(DESTDIR)$(PREFIX)/bin/doubletake-ctl
	rm -f $(DESTDIR)$(MANDIR)/man1/doubletake.1
	rm -f $(DESTDIR)$(MANDIR)/man1/doubletake-ctl.1
	rm -f $(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service

clean:
	rm -rf bin/
	go clean -testcache
