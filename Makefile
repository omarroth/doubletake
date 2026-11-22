.PHONY: all doubletake doubletake-native doubletake-ctl doubletake-test-receiver
.PHONY: release package-release install install-prebuilt uninstall test test-go clean

PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man
SYSTEMDUSERDIR ?= $(PREFIX)/lib/systemd/user
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
LICENSEDIR ?= $(PREFIX)/share/licenses/doubletake
BUILD_DIR ?= bin
RELEASE_DIR ?=
DISTDIR ?= dist
# Installing prebuilt files needs only the host platform or an explicit GOOS.
INSTALL_EXE := $(if $(strip $(GOOS)),$(if $(filter windows,$(GOOS)),.exe),$(if $(filter Windows_NT,$(OS)),.exe))
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
TARGET ?= $(GOOS)-$(patsubst amd64,x86_64,$(GOARCH))
release_dir = $(or $(RELEASE_DIR),$(BUILD_DIR)/release/$(TARGET))
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || printf 0)
BUILD_TAGS ?= $(if $(filter linux,$(GOOS)),fdk_aac)
EXE = $(if $(filter windows,$(GOOS)),.exe)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf devel)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
VERSION_FLAGS = -X doubletake/internal/version.Version=$(VERSION) -X doubletake/internal/version.Commit=$(COMMIT)

all: doubletake doubletake-ctl

doubletake:
	CGO_ENABLED=1 go build -tags '$(BUILD_TAGS)' -ldflags='$(VERSION_FLAGS)' -o '$(BUILD_DIR)/doubletake$(EXE)' ./cmd/doubletake

# Native desktop capture on macOS/Windows, audio-only on Linux.
doubletake-native:
	CGO_ENABLED=$(if $(filter linux,$(GOOS)),0,1) go build -trimpath -tags no_gstreamer -ldflags='$(VERSION_FLAGS)' -o '$(BUILD_DIR)/native/$(TARGET)/doubletake$(EXE)' ./cmd/doubletake

doubletake-ctl:
	CGO_ENABLED=0 go build -ldflags='$(VERSION_FLAGS)' -o '$(BUILD_DIR)/doubletake-ctl$(EXE)' ./cmd/doubletake-ctl

# Developer-only diagnostic receiver; build explicitly when needed.
doubletake-test-receiver:
	CGO_ENABLED=1 go build -tags '$(BUILD_TAGS)' -o '$(BUILD_DIR)/doubletake-test-receiver$(EXE)' ./cmd/doubletake-test-receiver

release:
	CGO_ENABLED=1 go build -trimpath -tags '$(BUILD_TAGS)' -ldflags='-s -w $(VERSION_FLAGS)' -o '$(release_dir)/doubletake$(EXE)' ./cmd/doubletake
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w $(VERSION_FLAGS)' -o '$(release_dir)/doubletake-ctl$(EXE)' ./cmd/doubletake-ctl
	$(MAKE) package-release

package-release:
	+SOURCE_DATE_EPOCH='$(SOURCE_DATE_EPOCH)' scripts/package-release.sh '$(VERSION)' '$(TARGET)' '$(release_dir)' '$(DISTDIR)'
	@set --; for target in linux-x86_64 linux-arm64; do \
		if test -f '$(DISTDIR)/doubletake-$(VERSION)-'$$target.tar.gz; then set -- "$$@" "$$target"; fi; \
	done; scripts/release-checksums.sh '$(DISTDIR)' '$(VERSION)' "$$@"

test:
	CGO_ENABLED=1 go test -tags '$(BUILD_TAGS)' ./...

test-go:
	CGO_ENABLED=0 go test ./...

install: all
	$(MAKE) install-prebuilt

# Packaging can install existing binaries without invoking the Go compiler.
install-prebuilt:
	install -d '$(DESTDIR)$(PREFIX)/bin'
	install -m 755 '$(BUILD_DIR)/doubletake$(INSTALL_EXE)' '$(BUILD_DIR)/doubletake-ctl$(INSTALL_EXE)' '$(DESTDIR)$(PREFIX)/bin/'
	install -d '$(DESTDIR)$(MANDIR)/man1'
	install -m 644 man/man1/doubletake.1 man/man1/doubletake-ctl.1 '$(DESTDIR)$(MANDIR)/man1/'
	install -d '$(DESTDIR)$(SYSTEMDUSERDIR)'
	sed 's|@bindir@|$(PREFIX)/bin|g' systemd/doubletake.service.in > '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'
	chmod 644 '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'
	install -d '$(DESTDIR)$(BASHCOMPDIR)'
	install -m 644 completions/doubletake.bash '$(DESTDIR)$(BASHCOMPDIR)/doubletake'
	ln -sf doubletake '$(DESTDIR)$(BASHCOMPDIR)/doubletake-ctl'
	install -d '$(DESTDIR)$(LICENSEDIR)'
	install -m 644 LICENSE COPYING.GPL '$(DESTDIR)$(LICENSEDIR)/'

uninstall:
	rm -f '$(DESTDIR)$(PREFIX)/bin/doubletake$(INSTALL_EXE)' '$(DESTDIR)$(PREFIX)/bin/doubletake-ctl$(INSTALL_EXE)'
	rm -f '$(DESTDIR)$(MANDIR)/man1/doubletake.1' '$(DESTDIR)$(MANDIR)/man1/doubletake-ctl.1'
	rm -f '$(DESTDIR)$(SYSTEMDUSERDIR)/doubletake.service'
	rm -f '$(DESTDIR)$(BASHCOMPDIR)/doubletake' '$(DESTDIR)$(BASHCOMPDIR)/doubletake-ctl'
	rm -f '$(DESTDIR)$(LICENSEDIR)/LICENSE' '$(DESTDIR)$(LICENSEDIR)/COPYING.GPL'

clean:
	rm -f -- doubletake doubletake.exe doubletake-ctl doubletake-ctl.exe \
		doubletake-test-receiver doubletake-test-receiver.exe doubletake-manpages.tar.gz SHA256SUMS
	@set -e; \
	build='$(BUILD_DIR)'; release='$(RELEASE_DIR)'; dist='$(DISTDIR)'; \
	case "$$build" in \
		bin|bin/|./bin|./bin/|'$(CURDIR)/bin'|'$(CURDIR)/bin/') rm -rf -- bin ;; \
		'') ;; \
		*) rm -f -- "$$build"/doubletake "$$build"/doubletake.exe \
			"$$build"/doubletake-ctl "$$build"/doubletake-ctl.exe \
			"$$build"/doubletake-test-receiver "$$build"/doubletake-test-receiver.exe \
			"$$build"/native/*/doubletake "$$build"/native/*/doubletake.exe \
			"$$build"/release/*/doubletake "$$build"/release/*/doubletake.exe \
			"$$build"/release/*/doubletake-ctl "$$build"/release/*/doubletake-ctl.exe ;; \
	esac; \
	if [ -n "$$release" ]; then \
		rm -f -- "$$release"/doubletake "$$release"/doubletake.exe \
			"$$release"/doubletake-ctl "$$release"/doubletake-ctl.exe; \
	fi; \
	case "$$dist" in \
		dist|dist/|./dist|./dist/|'$(CURDIR)/dist'|'$(CURDIR)/dist/') rm -rf -- dist ;; \
		'') ;; \
		*) rm -f -- "$$dist"/doubletake-*-linux-x86_64.tar.gz \
			"$$dist"/doubletake-*-linux-arm64.tar.gz "$$dist"/doubletake-*-macos-universal.tar.gz \
			"$$dist"/doubletake-*-windows-x86_64.zip "$$dist"/doubletake-*-windows-arm64.zip \
			"$$dist"/SHA256SUMS ;; \
	esac
