// Package osdetect performs basic OS fingerprinting based on TTL and TCP window size.
package osdetect

import "strings"

// Result holds the OS detection guess.
type Result struct {
	OS         string
	Confidence string // "high", "medium", "low"
	Details    string
}

// GuessByTTL returns a best-guess OS based on the observed IP TTL.
// Typical defaults:
//
//	1–64   → Linux / macOS / FreeBSD
//	65–128 → Windows
//	129–255 → Cisco / Solaris / other network devices
func GuessByTTL(ttl int) Result {
	switch {
	case ttl >= 1 && ttl <= 64:
		return Result{OS: "Linux/macOS/BSD", Confidence: "medium",
			Details: "TTL 1–64 typical of Linux, macOS, or BSD"}
	case ttl >= 65 && ttl <= 128:
		return Result{OS: "Windows", Confidence: "medium",
			Details: "TTL 65–128 typical of Windows"}
	case ttl >= 129 && ttl <= 255:
		return Result{OS: "Network device / Solaris", Confidence: "low",
			Details: "TTL 129–255 typical of network equipment or Solaris"}
	default:
		return Result{OS: "Unknown", Confidence: "low", Details: "TTL out of expected range"}
	}
}

// GuessByBanner refines the OS guess using service banners.
func GuessByBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "windows"):
		return "Windows"
	case strings.Contains(b, "ubuntu"):
		return "Linux (Ubuntu)"
	case strings.Contains(b, "debian"):
		return "Linux (Debian)"
	case strings.Contains(b, "centos"):
		return "Linux (CentOS)"
	case strings.Contains(b, "fedora"):
		return "Linux (Fedora)"
	case strings.Contains(b, "red hat"):
		return "Linux (Red Hat)"
	case strings.Contains(b, "freebsd"):
		return "FreeBSD"
	case strings.Contains(b, "openbsd"):
		return "OpenBSD"
	case strings.Contains(b, "darwin"):
		return "macOS"
	case strings.Contains(b, "cisco"):
		return "Cisco IOS"
	default:
		return ""
	}
}
