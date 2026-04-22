package scanner

import (
	"encoding/binary"
	"math/rand"
	"net"
	"syscall"
	"time"
)

// synScan sends a TCP SYN packet using a raw socket and interprets the response.
// Requires root/CAP_NET_RAW.  Falls back to tcpConnect if raw socket fails.
func synScan(ip string, port int, timeout time.Duration) PortState {
	// Ephemeral source port in the range 10000–65535 (55536 possible values).
	src := uint16(rand.Intn(55536) + 10000) //nolint:gosec // not cryptographic

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		// No permission → fall back to connect scan
		return tcpConnect(ip, port, timeout)
	}
	defer syscall.Close(fd)

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		return StateFiltered
	}

	// port is already validated to be in [1, 65535] by the port parser.
	if port < 1 || port > 65535 {
		return StateFiltered
	}
	dstPort := uint16(port) //nolint:gosec // bounds checked above

	pkt := buildSYN(src, dstPort, dstIP)

	var dst syscall.SockaddrInet4
	copy(dst.Addr[:], dstIP)
	dst.Port = port

	if err := syscall.Sendto(fd, pkt, 0, &dst); err != nil {
		return StateFiltered
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		_ = syscall.SetNonblock(fd, false)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			continue
		}
		// IP header is variable length; skip it
		ihl := int(buf[0]&0x0F) * 4
		if n < ihl+20 {
			continue
		}
		tcp := buf[ihl : ihl+20]
		// Check source port matches our destination
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		if int(srcPort) != port {
			continue
		}
		flags := tcp[13]
		const SYN = 0x02
		const ACK = 0x10
		const RST = 0x04
		if flags&(SYN|ACK) == (SYN | ACK) {
			// Send RST to close the half-open connection
			rstPkt := buildRST(src, dstPort, dstIP, binary.BigEndian.Uint32(tcp[8:12]))
			_ = syscall.Sendto(fd, rstPkt, 0, &dst)
			return StateOpen
		}
		if flags&RST != 0 {
			return StateClosed
		}
	}
	return StateFiltered
}

// buildSYN builds a raw TCP SYN packet (no IP header — kernel fills it).
func buildSYN(srcPort, dstPort uint16, dstIP net.IP) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(pkt[4:8], uint32(rand.Int31())) //nolint:gosec
	binary.BigEndian.PutUint32(pkt[8:12], 0)                   // ack
	pkt[12] = 0x50                                              // data offset = 5 * 4 = 20 bytes
	pkt[13] = 0x02                                              // SYN
	binary.BigEndian.PutUint16(pkt[14:16], 65535)              // window size
	// checksum
	binary.BigEndian.PutUint16(pkt[16:18], tcpChecksum(pkt, net.IPv4(0, 0, 0, 0).To4(), dstIP))
	return pkt
}

// buildRST builds a TCP RST packet.
func buildRST(srcPort, dstPort uint16, dstIP net.IP, ack uint32) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(pkt[4:8], 0)
	binary.BigEndian.PutUint32(pkt[8:12], ack)
	pkt[12] = 0x50
	pkt[13] = 0x04 // RST
	binary.BigEndian.PutUint16(pkt[14:16], 0)
	binary.BigEndian.PutUint16(pkt[16:18], tcpChecksum(pkt, net.IPv4(0, 0, 0, 0).To4(), dstIP))
	return pkt
}

// tcpChecksum computes the TCP checksum with a pseudo-header.
func tcpChecksum(tcp, srcIP, dstIP net.IP) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	// zero out checksum field in copy
	pseudo[12+16] = 0
	pseudo[12+17] = 0
	return checksum(pseudo)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// synOrConnect performs a SYN scan, falling back to connect scan if needed.
func synOrConnect(ip string, port int, timeout time.Duration) PortState {
	return synScan(ip, port, timeout)
}

