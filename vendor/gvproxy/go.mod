// Pinned build module for the gvproxy switch (gvisor-tap-vsock).
// minimald spawns this binary as the per-host userspace switch (UC1/UC6).
// Built from source at a pinned version with a checked-in go.sum so the
// dependency graph is cryptographically verified (not a pre-built download).
module github.com/gominimal/minimal/vendor/gvproxy

go 1.25.0

require github.com/containers/gvisor-tap-vsock v0.8.9

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/apparentlymart/go-cidr v1.1.1 // indirect
	github.com/containers/winquit v1.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/inetaf/tcpproxy v0.0.0-20250222171855-c4b9df066048 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20240710054256-ddd8a41251c9 // indirect
	github.com/linuxkit/virtsock v0.0.0-20220523201153-1a23e78aa7a2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mdlayher/vsock v1.2.1 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20240916094835-a174eb65023f // indirect
)
