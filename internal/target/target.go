// Package target parses and expands scan targets into individual IP addresses.
package target

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// Expand returns all IP addresses described by the given target string.
// Supported formats:
//   - Single IPv4/IPv6 address    "192.168.1.1"
//   - CIDR range                  "192.168.1.0/24"
//   - Octet range                 "192.168.1.1-10"
//   - Hostname                    "example.com"
func Expand(target string) ([]string, error) {
	// CIDR
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	// Octet dash range: 192.168.1.1-10
	if strings.Contains(target, "-") {
		return expandRange(target)
	}
	// Hostname → resolve to IPs
	if ip := net.ParseIP(target); ip == nil {
		addrs, err := net.LookupHost(target)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", target, err)
		}
		return addrs, nil
	}
	return []string{target}, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	_ = ip

	var ips []string
	for addr := cloneIP(network.IP); network.Contains(addr); incIP(addr) {
		ips = append(ips, addr.String())
	}
	return ips, nil
}

func expandRange(target string) ([]string, error) {
	// Expect format: A.B.C.start-end
	dashIdx := strings.LastIndex(target, "-")
	if dashIdx < 0 {
		return nil, fmt.Errorf("invalid range %q", target)
	}
	base := target[:dashIdx]
	endStr := target[dashIdx+1:]

	// Find last dot to extract prefix and start
	dotIdx := strings.LastIndex(base, ".")
	if dotIdx < 0 {
		return nil, fmt.Errorf("invalid range %q", target)
	}
	prefix := base[:dotIdx]
	startStr := base[dotIdx+1:]

	start, err := strconv.Atoi(startStr)
	if err != nil || start < 0 || start > 255 {
		return nil, fmt.Errorf("invalid range start %q in %q", startStr, target)
	}
	end, err := strconv.Atoi(endStr)
	if err != nil || end < 0 || end > 255 {
		return nil, fmt.Errorf("invalid range end %q in %q", endStr, target)
	}
	if start > end {
		return nil, fmt.Errorf("range start > end in %q", target)
	}

	var ips []string
	for i := start; i <= end; i++ {
		candidate := fmt.Sprintf("%s.%d", prefix, i)
		if net.ParseIP(candidate) == nil {
			return nil, fmt.Errorf("invalid IP %q in range expansion", candidate)
		}
		ips = append(ips, candidate)
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	n := new(big.Int).SetBytes(ip)
	n.Add(n, big.NewInt(1))
	b := n.Bytes()
	// Pad to original length
	if len(b) < len(ip) {
		padded := make([]byte, len(ip))
		copy(padded[len(ip)-len(b):], b)
		copy(ip, padded)
	} else {
		copy(ip, b[len(b)-len(ip):])
	}
}
