// Package version carries build-time version information injected via -ldflags.
package version

// Version is set at build time (see Makefile). "dev" when built without ldflags.
var Version = "dev"
