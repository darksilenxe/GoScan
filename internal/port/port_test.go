package port_test

import (
	"testing"

	"github.com/darksilenxe/goscan/internal/port"
)

func TestParseSingle(t *testing.T) {
	ports, err := port.Parse("80")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("expected [80], got %v", ports)
	}
}

func TestParseCommaSeparated(t *testing.T) {
	ports, err := port.Parse("22,80,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d: %v", len(ports), ports)
	}
}

func TestParseRange(t *testing.T) {
	ports, err := port.Parse("8080-8085")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 6 {
		t.Fatalf("expected 6 ports, got %d: %v", len(ports), ports)
	}
	if ports[0] != 8080 || ports[5] != 8085 {
		t.Fatalf("unexpected range: %v", ports)
	}
}

func TestParseAllPorts(t *testing.T) {
	ports, err := port.Parse("-")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 65535 {
		t.Fatalf("expected 65535 ports, got %d", len(ports))
	}
}

func TestParseDeduplication(t *testing.T) {
	ports, err := port.Parse("80,80,80")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected deduplication to 1 port, got %d", len(ports))
	}
}

func TestParseInvalid(t *testing.T) {
	for _, bad := range []string{"0", "65536", "abc", "1-0"} {
		_, err := port.Parse(bad)
		if err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestCommonPortsNotEmpty(t *testing.T) {
	if len(port.CommonPorts) == 0 {
		t.Fatal("CommonPorts should not be empty")
	}
}
