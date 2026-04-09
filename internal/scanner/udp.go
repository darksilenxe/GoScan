package scanner

import (
	"fmt"
	"net"
	"time"
)

// udpScan sends an empty UDP datagram and infers port state from the response.
// Requires root/CAP_NET_RAW for ICMP unreachable detection.
// Falls back to a best-effort approach otherwise.
func udpScan(ip string, port int, timeout time.Duration) PortState {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return StateFiltered
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send empty payload
	_, err = conn.Write([]byte{})
	if err != nil {
		return StateFiltered
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		if isTimeout(err) {
			// No response → open|filtered (UDP doesn't respond when open)
			return StateOpenFiltered
		}
		// ICMP port unreachable typically manifests as "connection refused" on Linux
		return StateClosed
	}
	// Got a response → open
	return StateOpen
}
