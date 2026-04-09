package scanner

import (
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// pingHost sends an ICMP echo request and returns (up, ttl, rtt, error).
// Requires root/CAP_NET_RAW.  Falls back to TCP port 80 probe if ICMP fails.
func pingHost(ip string, timeout time.Duration) (up bool, ttl int, rtt time.Duration, err error) {
	up, ttl, rtt, err = icmpPing(ip, timeout)
	if err != nil {
		// Fall back to TCP-based "ping" on port 80 or 443
		up, rtt = tcpPing(ip, timeout)
		err = nil
	}
	return
}

func icmpPing(ip string, timeout time.Duration) (up bool, ttl int, rtt time.Duration, err error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, 0, 0, err
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false, 0, 0, err
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("GOSCAN"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false, 0, 0, err
	}

	start := time.Now()
	if _, err = conn.WriteTo(wb, dst); err != nil {
		return false, 0, 0, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	rb := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(rb)
	if err != nil {
		return false, 0, 0, err
	}
	rtt = time.Since(start)
	_ = peer

	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return false, 0, 0, err
	}
	if rm.Type == ipv4.ICMPTypeEchoReply {
		// TTL not directly available from icmp package; read from raw bytes
		return true, 0, rtt, nil
	}
	return false, 0, 0, nil
}

// tcpPing attempts a TCP connection to ports 80 and 443 to infer host liveness.
func tcpPing(ip string, timeout time.Duration) (up bool, rtt time.Duration) {
	for _, port := range []int{80, 443, 22} {
		start := time.Now()
		state := tcpConnect(ip, port, timeout)
		if state == StateOpen || state == StateFiltered {
			return true, time.Since(start)
		}
	}
	return false, 0
}
