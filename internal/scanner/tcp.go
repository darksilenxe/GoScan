package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// tcpConnect attempts a full TCP three-way handshake to the given host:port.
// Returns StateOpen on success, StateFiltered on timeout, StateClosed on RST/refused.
func tcpConnect(ip string, port int, timeout time.Duration) PortState {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if isTimeout(err) {
			return StateFiltered
		}
		return StateClosed
	}
	conn.Close()
	return StateOpen
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	// "connection refused" → closed; "i/o timeout" / "no route" → filtered
	msg := err.Error()
	for _, kw := range []string{"timeout", "timed out", "no route", "host unreachable", "network unreachable"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

