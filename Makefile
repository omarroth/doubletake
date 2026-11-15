.PHONY: all build doubletake doubletake-ctl doubletake-gstreamer-cgo doubletake-test-receiver release doubletake-release doubletake-ctl-release manpages-release install install-bin install-man install-systemd uninstall test test-go test-gstreamer clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user
BUILD_TAGS ?= gstreamer_cgo
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf devel)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
VERSION_FLAGS = -X doubletake/internal/version.Version=$(VERSION) -X doubletake/internal/version.Commit=$(COMMIT)

all: doubletake doubletake-ctl

build: all

doubletake:
	CGO_ENABLED=1 go build -tags '$(BUILD_TAGS)' -ldflags='$(VERSION_FLAGS)' -o bin/doubletake ./cmd/doubletake

doubletake-ctl:
	CGO_ENABLED=0 go build -ldflags='$(VERSION_FLAGS)' -o bin/doubletake-ctl ./cmd/doubletake-ctl

# Compatibility alias for the prototype target name.
doubletake-gstreamer-cgo: doubletake

# Developer-only diagnostic receiver; build explicitly when needed.
doubletake-test-receiver:
	go build -o bin/doubletake-test-receiver ./cmd/doubletake-test-receiver

doubletake-release:
	CGO_ENABLED=1 go build -trimpath -tags '$(BUILD_TAGS)' -ldflags='-s -w $(VERSION_FLAGS)' -o doubletake ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w $(VERSION_FLAGS)' -o doubletake-ctl ./cmd/doubletake-ctl

manpages-release:
	tar -czf doubletake-manpages.tar.gz -C man man1/doubletake.1 man1/doubletake-ctl.1

release: doubletake-release doubletake-ctl-release manpages-release
	sha256sum doubletake doubletake-ctl doubletake-manpages.tar.gz LICENSE COPYING.GPL > SHA256SUMS

test: test-gstreamer

test-go:
	CGO_ENABLED=0 go test ./...

test-gstreamer:
	CGO_ENABLED=1 go test -tags '$(BUILD_TAGS)' ./...

install: install-bin install-man install-systemd

install-bin: all
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
	rm -f doubletake doubletake-ctl doubletake-manpages.tar.gz SHA256SUMS
	go clean -testcache
