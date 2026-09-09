package main

import "testing"

func TestListenAddressDefaultsToLoopback(t *testing.T) {
	t.Setenv("KENATO_LISTEN_ADDR", "")
	if got := listenAddress(); got != defaultListenAddress {
		t.Fatalf("listenAddress() = %q, want %q", got, defaultListenAddress)
	}
}

func TestListenAddressUsesExplicitOverride(t *testing.T) {
	const address = "0.0.0.0:9090"
	t.Setenv("KENATO_LISTEN_ADDR", address)
	if got := listenAddress(); got != address {
		t.Fatalf("listenAddress() = %q, want %q", got, address)
	}
}
