//go:build tools
// +build tools

// Package tools pins the gvproxy command in the module graph so
// `go build github.com/containers/gvisor-tap-vsock/cmd/gvproxy` resolves
// against the version pinned in go.mod / go.sum.
package tools

import _ "github.com/containers/gvisor-tap-vsock/cmd/gvproxy"
