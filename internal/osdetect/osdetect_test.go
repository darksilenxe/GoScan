package osdetect_test

import (
	"testing"

	"github.com/darksilenxe/goscan/internal/osdetect"
)

func TestGuessByTTL(t *testing.T) {
	tests := []struct {
		ttl    int
		wantOS string
	}{
		{64, "Linux/macOS/BSD"},
		{1, "Linux/macOS/BSD"},
		{32, "Linux/macOS/BSD"},
		{65, "Windows"},
		{128, "Windows"},
		{129, "Network device / Solaris"},
		{255, "Network device / Solaris"},
	}
	for _, tt := range tests {
		r := osdetect.GuessByTTL(tt.ttl)
		if r.OS != tt.wantOS {
			t.Errorf("TTL %d: expected %q, got %q", tt.ttl, tt.wantOS, r.OS)
		}
	}
}

func TestGuessByBanner(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH Ubuntu 20.04", "Linux (Ubuntu)"},
		{"Microsoft-IIS/10.0 Windows Server", "Windows"},
		{"FreeBSD 13.0", "FreeBSD"},
		{"totally unknown banner", ""},
	}
	for _, tt := range tests {
		got := osdetect.GuessByBanner(tt.banner)
		if got != tt.want {
			t.Errorf("banner %q: expected %q, got %q", tt.banner, tt.want, got)
		}
	}
}
