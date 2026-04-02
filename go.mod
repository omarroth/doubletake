module airplay

go 1.23

require (
	github.com/blacktop/go-macho v1.1.234
	github.com/godbus/dbus/v5 v5.1.0
	github.com/grandcat/zeroconf v1.0.0
	github.com/unicorn-engine/unicorn v0.0.0-20241221030228-28990888443e
	golang.org/x/crypto v0.31.0
	howett.net/plist v1.0.1
)

replace github.com/blacktop/go-macho v1.1.234 => github.com/t0rr3sp3dr0/go-macho v0.0.0-20241224072836-20948aaf41de

require (
	github.com/blacktop/go-dwarf v1.0.10 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/miekg/dns v1.1.62 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
)
