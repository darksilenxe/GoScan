package target_test

import (
	"testing"

	"github.com/darksilenxe/goscan/internal/target"
)

func TestExpandSingleIP(t *testing.T) {
	ips, err := target.Expand("192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Fatalf("expected [192.168.1.1], got %v", ips)
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := target.Expand("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	// /30 → network (.0), host1 (.1), host2 (.2), broadcast (.3) = 4 addresses
	if len(ips) != 4 {
		t.Fatalf("expected 4 IPs for /30, got %d: %v", len(ips), ips)
	}
}

func TestExpandRange(t *testing.T) {
	ips, err := target.Expand("10.0.0.5-8")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"}
	if len(ips) != len(want) {
		t.Fatalf("expected %v, got %v", want, ips)
	}
	for i, ip := range ips {
		if ip != want[i] {
			t.Errorf("index %d: expected %s, got %s", i, want[i], ip)
		}
	}
}

func TestExpandRangeInvalid(t *testing.T) {
	_, err := target.Expand("10.0.0.10-5") // start > end
	if err == nil {
		t.Fatal("expected error for start > end range")
	}
}

func TestExpandCIDRInvalid(t *testing.T) {
	_, err := target.Expand("999.0.0.0/8")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
