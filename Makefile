.PHONY: all build doubletake doubletake-ctl doubletake-gstreamer-cgo doubletake-test-receiver macos-audio-helper release doubletake-release doubletake-ctl-release package-release install install-prebuilt install-bin install-man install-systemd install-completion install-license uninstall test test-go test-gstreamer clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
LICENSEDIR ?= $(PREFIX)/share/licenses/doubletake
BUILD_DIR ?= bin
TARGET ?= $(shell go env GOOS)-$(shell go env GOARCH | sed 's/^amd64$$/x86_64/')
RELEASE_DIR ?= bin/release/$(TARGET)
DISTDIR ?= dist
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || printf 0)
BUILD_TAGS ?= gstreamer_cgo fdk_aac
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf devel)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
VERSION_FLAGS = -X doubletake/internal/version.Version=$(VERSION) -X doubletake/internal/version.Commit=$(COMMIT)

all: doubletake doubletake-ctl

build: all

doubletake:
	CGO_ENABLED=1 go build -tags '$(BUILD_TAGS)' -ldflags='$(VERSION_FLAGS)' -o '$(BUILD_DIR)/doubletake' ./cmd/doubletake

doubletake-ctl:
	CGO_ENABLED=0 go build -ldflags='$(VERSION_FLAGS)' -o '$(BUILD_DIR)/doubletake-ctl' ./cmd/doubletake-ctl

macos-audio-helper:
	install -d '$(BUILD_DIR)'
	xcrun --sdk macosx swiftc -O -parse-as-library -swift-version 5 -target "$$(uname -m)-apple-macosx13.0" \
		-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker 'platform/macos/audio-info.plist' \
		-o '$(BUILD_DIR)/doubletake-macos-audio' platform/macos/audio.swift

# Compatibility alias for the prototype target name.
doubletake-gstreamer-cgo: doubletake

# Developer-only diagnostic receiver; build explicitly when needed.
doubletake-test-receiver:
	CGO_ENABLED=1 go build -tags '$(BUILD_TAGS)' -o '$(BUILD_DIR)/doubletake-test-receiver' ./cmd/doubletake-test-receiver

doubletake-release:
	CGO_ENABLED=1 go build -trimpath -tags '$(BUILD_TAGS)' -ldflags='-s -w $(VERSION_FLAGS)' -o '$(RELEASE_DIR)/doubletake' ./cmd/doubletake

doubletake-ctl-release:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w $(VERSION_FLAGS)' -o '$(RELEASE_DIR)/doubletake-ctl' ./cmd/doubletake-ctl

package-release:
	+SOURCE_DATE_EPOCH='$(SOURCE_DATE_EPOCH)' scripts/package-release.sh '$(VERSION)' '$(TARGET)' '$(RELEASE_DIR)' '$(DISTDIR)'
	@set --; for target in linux-x86_64 linux-arm64; do \
		if test -f '$(DISTDIR)/doubletake-$(VERSION)-'$$target.tar.gz; then set -- "$$@" "$$target"; fi; \
	done; scripts/release-checksums.sh '$(DISTDIR)' '$(VERSION)' "$$@"

release: doubletake-release doubletake-ctl-release
	$(MAKE) package-release

test: test-gstreamer

test-go:
	CGO_ENABLED=0 go test ./...

test-gstreamer:
	CGO_ENABLED=1 go test -tags '$(BUILD_TAGS)' ./...

install: all
	$(MAKE) install-prebuilt

# Packaging can install existing binaries without invoking the Go compiler.
install-prebuilt: install-bin install-man install-systemd install-completion install-license

install-bin:
	install -d '$(DESTDIR)$(PREFIX)/bin'
	install -m 755 '$(BUILD_DIR)/doubletake' '$(DESTDIR)$(PREFIX)/bin/'
	install -m 755 '$(BUILD_DIR)/doubletake-ctl' '$(DESTDIR)$(PREFIX)/bin/'

install-man:
	install -d '$(DESTDIR)$(MANDIR)/man1'
	install -m 644 man/man1/doubletake.1 '$(DESTDIR)$(MANDIR)/man1/'
	install -m 644 man/man1/doubletake-ctl.1 '$(DESTDIR)$(MANDIR)/man1/'

install-systemd:
	install -d '$(DESTDIR)$(SYSTEMDUSERDIR)'
	sed 's|@bindir@|$(PREFIX)/bin|g' systemd/doubletake.service.in > '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'
	chmod 644 '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'

install-completion:
	install -d '$(DESTDIR)$(BASHCOMPDIR)'
	install -m 644 completions/doubletake.bash '$(DESTDIR)$(BASHCOMPDIR)/doubletake'
	ln -sf doubletake '$(DESTDIR)$(BASHCOMPDIR)/doubletake-ctl'

install-license:
	install -d '$(DESTDIR)$(LICENSEDIR)'
	install -m 644 LICENSE COPYING.GPL '$(DESTDIR)$(LICENSEDIR)/'

uninstall:
	rm -f '$(DESTDIR)$(PREFIX)/bin/doubletake' '$(DESTDIR)$(PREFIX)/bin/doubletake-ctl'
	rm -f '$(DESTDIR)$(MANDIR)/man1/doubletake.1' '$(DESTDIR)$(MANDIR)/man1/doubletake-ctl.1'
	rm -f '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'
	rm -f '$(DESTDIR)$(BASHCOMPDIR)/doubletake' '$(DESTDIR)$(BASHCOMPDIR)/doubletake-ctl'
	rm -f '$(DESTDIR)$(LICENSEDIR)/LICENSE' '$(DESTDIR)$(LICENSEDIR)/COPYING.GPL'

clean:
	rm -rf bin/ dist/
	rm -f doubletake doubletake-ctl doubletake-manpages.tar.gz SHA256SUMS
	go clean -testcache
