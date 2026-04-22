// Package scanner — main scan orchestrator.
package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/darksilenxe/goscan/internal/osdetect"
	"github.com/darksilenxe/goscan/internal/service"
)

// Scanner orchestrates host and port scanning.
type Scanner struct {
	opts Options
}

// New returns a configured Scanner.
func New(opts Options) *Scanner {
	if opts.Parallelism <= 0 {
		opts.Parallelism = 100
	}
	if opts.MaxHostConc <= 0 {
		opts.MaxHostConc = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	if opts.HostTimeout <= 0 {
		opts.HostTimeout = 5 * time.Minute
	}
	return &Scanner{opts: opts}
}

// ScanHosts scans a list of IP strings and returns results via the result channel.
// The channel is closed when all hosts are done.
func (s *Scanner) ScanHosts(ctx context.Context, hosts []string) <-chan HostResult {
	out := make(chan HostResult, len(hosts))
	sem := make(chan struct{}, s.opts.MaxHostConc)

	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			result := s.scanHost(ctx, host)
			out <- result
		}(h)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (s *Scanner) scanHost(ctx context.Context, ip string) HostResult {
	start := time.Now()
	result := HostResult{
		IP:        ip,
		StartTime: start,
	}

	// Resolve hostname
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	// Host discovery
	if !s.opts.SkipPing {
		up, ttl, latency, _ := pingHost(ip, s.opts.Timeout*2)
		if !up && !s.opts.PingScan {
			// Try a quick connect to see if host responds at all
			up, latency = tcpPing(ip, s.opts.Timeout)
		}
		result.IsUp = up
		result.TTL = ttl
		result.Latency = latency
		if !up {
			result.EndTime = time.Now()
			return result
		}
	} else {
		result.IsUp = true
	}

	if s.opts.PingScan {
		result.EndTime = time.Now()
		return result
	}

	// OS detection (TTL-based)
	if s.opts.OSDetect && result.TTL > 0 {
		osResult := osdetect.GuessByTTL(result.TTL)
		result.OS = osResult.OS
		result.OSDetails = osResult.Details
	}

	// Port scanning
	hostCtx, cancel := context.WithTimeout(ctx, s.opts.HostTimeout)
	defer cancel()

	result.Ports = s.scanPorts(hostCtx, ip)

	// Refine OS guess from banners
	if s.opts.OSDetect && result.OS == "" {
		for _, p := range result.Ports {
			if guess := osdetect.GuessByBanner(p.Banner); guess != "" {
				result.OS = guess
				break
			}
		}
	}

	result.EndTime = time.Now()
	return result
}

func (s *Scanner) scanPorts(ctx context.Context, ip string) []PortResult {
	sem := make(chan struct{}, s.opts.Parallelism)
	results := make([]PortResult, len(s.opts.Ports))
	var wg sync.WaitGroup

	for i, p := range s.opts.Ports {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = s.scanPort(ip, port)
		}(i, p)
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanPort(ip string, port int) PortResult {
	proto := "tcp"
	if s.opts.ScanType == ScanUDP {
		proto = "udp"
	}

	var state PortState
	switch s.opts.ScanType {
	case ScanSYN:
		state = synOrConnect(ip, port, s.opts.Timeout)
	case ScanUDP:
		state = udpScan(ip, port, s.opts.Timeout)
	default: // ScanTCP
		state = tcpConnect(ip, port, s.opts.Timeout)
	}

	svcName := service.Name(port, proto)
	pr := PortResult{
		Port:    port,
		Proto:   proto,
		State:   state,
		Service: svcName,
	}

	// Service/version detection via banner grab (TCP only, open ports)
	if s.opts.ServiceDetect && state == StateOpen && proto == "tcp" {
		banner := service.GrabBanner(ip, port, s.opts.Timeout*2)
		if banner != "" {
			pr.Banner = truncate(banner, 200)
			pr.Version = extractVersion(banner)
			// Refine OS from banner
		}
	}

	return pr
}

// truncate limits a string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// extractVersion attempts to pull a version string from a banner.
func extractVersion(banner string) string {
	// First line of the banner often contains the version
	for i, c := range banner {
		if c == '\n' || c == '\r' {
			return banner[:i]
		}
	}
	return banner
}
