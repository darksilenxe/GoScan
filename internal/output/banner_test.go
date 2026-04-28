package output

import (
	"strings"
	"testing"
)

func TestStartupBannerAtCoversAllFrames(t *testing.T) {
	frameMarkers := []string{
		"|      (^_^) /               |",
		"|               \\ (^_^)      |",
		"|          \\o(^_^)o/         |",
	}

	for i, marker := range frameMarkers {
		banner := startupBannerAt(i)
		if !strings.Contains(banner, "GoScan is starting!") {
			t.Fatalf("frame %d is missing startup text", i)
		}
		if !strings.Contains(banner, marker) {
			t.Fatalf("frame %d is missing its expected marker", i)
		}
	}
}
