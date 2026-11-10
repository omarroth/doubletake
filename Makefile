.PHONY: all build doubletake doubletake-static doubletake-ctl doubletake-gstreamer-cgo doubletake-test-receiver doubletake-release doubletake-static-release doubletake-ctl-release manpages-release install install-bin install-man install-systemd uninstall test test-gstreamer clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user

all: doubletake doubletake-static doubletake-ctl

build: all

doubletake:
	CGO_ENABLED=1 go build -tags gstreamer_cgo -o bin/doubletake ./cmd/doubletake

# Portable fallback. Video runs through gst-launch-1.0, so the encoder cannot be
# adjusted while streaming and automatic quality adaptation is unavailable.
doubletake-static:
	CGO_ENABLED=0 go build -o bin/doubletake-static ./cmd/doubletake

doubletake-ctl:
	CGO_ENABLED=0 go build -o bin/doubletake-ctl ./cmd/doubletake-ctl

# Compatibility alias for the prototype target name.
doubletake-gstreamer-cgo: doubletake

# Developer-only diagnostic receiver; build explicitly when needed.
doubletake-test-receiver:
	go build -o bin/doubletake-test-receiver ./cmd/doubletake-test-receiver

doubletake-release:
	CGO_ENABLED=1 go build -trimpath -tags gstreamer_cgo -ldflags='-s -w' -o doubletake ./cmd/doubletake

doubletake-static-release:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static' -o doubletake-static ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static' -o doubletake-ctl ./cmd/doubletake-ctl

manpages-release:
	tar -czf doubletake-manpages.tar.gz -C man man1/doubletake.1 man1/doubletake-ctl.1

test:
	go test ./...

test-gstreamer:
	CGO_ENABLED=1 go test -tags gstreamer_cgo ./...

install: all install-bin install-man install-systemd

install-bin:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 bin/doubletake $(DESTDIR)$(PREFIX)/bin/
	install -m 755 bin/doubletake-static $(DESTDIR)$(PREFIX)/bin/
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
	rm -f $(DESTDIR)$(PREFIX)/bin/doubletake-static
	rm -f $(DESTDIR)$(PREFIX)/bin/doubletake-ctl
	rm -f $(DESTDIR)$(MANDIR)/man1/doubletake.1
	rm -f $(DESTDIR)$(MANDIR)/man1/doubletake-ctl.1
	rm -f $(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service

clean:
	rm -rf bin/
	go clean -testcache
