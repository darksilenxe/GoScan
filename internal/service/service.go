// Package service maps port numbers to well-known service names and banners.
package service

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Name returns the well-known service name for a TCP or UDP port, or "unknown".
func Name(port int, proto string) string {
	key := fmt.Sprintf("%d/%s", port, proto)
	if name, ok := wellKnown[key]; ok {
		return name
	}
	return "unknown"
}

// GrabBanner attempts a TCP banner grab on the given address:port with a timeout.
// Returns the banner string (trimmed), or empty string on failure.
func GrabBanner(ip string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Some services send a banner immediately; others need a probe.
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}

	// Send HTTP probe and read response
	_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ = conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// wellKnown is a curated map of port/proto → service name.
var wellKnown = map[string]string{
	"1/tcp": "tcpmux", "7/tcp": "echo", "7/udp": "echo",
	"9/tcp": "discard", "9/udp": "discard", "13/tcp": "daytime",
	"17/tcp": "qotd", "19/tcp": "chargen", "20/tcp": "ftp-data",
	"21/tcp": "ftp", "22/tcp": "ssh", "23/tcp": "telnet",
	"25/tcp": "smtp", "37/tcp": "time", "43/tcp": "whois",
	"53/tcp": "domain", "53/udp": "domain", "67/udp": "dhcps",
	"68/udp": "dhcpc", "69/udp": "tftp", "79/tcp": "finger",
	"80/tcp": "http", "88/tcp": "kerberos-sec", "110/tcp": "pop3",
	"111/tcp": "rpcbind", "111/udp": "rpcbind", "113/tcp": "ident",
	"119/tcp": "nntp", "123/udp": "ntp", "135/tcp": "msrpc",
	"137/udp": "netbios-ns", "138/udp": "netbios-dgm", "139/tcp": "netbios-ssn",
	"143/tcp": "imap", "161/udp": "snmp", "162/udp": "snmptrap",
	"179/tcp": "bgp", "194/tcp": "irc", "199/tcp": "smux",
	"389/tcp": "ldap", "427/tcp": "svrloc", "427/udp": "svrloc",
	"443/tcp": "https", "444/tcp": "snpp", "445/tcp": "microsoft-ds",
	"465/tcp": "smtps", "500/udp": "isakmp", "514/tcp": "shell",
	"514/udp": "syslog", "515/tcp": "printer", "543/tcp": "klogin",
	"544/tcp": "kshell", "548/tcp": "afp", "554/tcp": "rtsp",
	"587/tcp": "submission", "631/tcp": "ipp", "636/tcp": "ldapssl",
	"646/tcp": "ldp", "873/tcp": "rsync", "990/tcp": "ftps",
	"993/tcp": "imaps", "995/tcp": "pop3s", "1025/tcp": "NFS-or-IIS",
	"1026/tcp": "LSA-or-nterm", "1027/tcp": "IIS", "1028/tcp": "unknown",
	"1029/tcp": "ms-lsa", "1110/tcp": "nfsd-status", "1433/tcp": "ms-sql-s",
	"1434/udp": "ms-sql-m", "1720/tcp": "H.323/Q.931", "1723/tcp": "pptp",
	"1755/tcp": "wms", "1900/udp": "upnp", "2000/tcp": "cisco-sccp",
	"2001/tcp": "dc", "2049/tcp": "nfs", "2049/udp": "nfs",
	"2121/tcp": "ccproxy-ftp", "2717/tcp": "pn-requester",
	"3000/tcp": "ppp", "3128/tcp": "squid-http", "3306/tcp": "mysql",
	"3389/tcp": "ms-wbt-server", "3986/tcp": "mapper-ws-ethd",
	"4899/tcp": "radmin", "5000/tcp": "upnp", "5009/tcp": "airport-admin",
	"5051/tcp": "ida-agent", "5060/tcp": "sip", "5060/udp": "sip",
	"5101/tcp": "admdog", "5190/tcp": "aol", "5357/tcp": "wsdapi",
	"5432/tcp": "postgresql", "5631/tcp": "pcanywheredata",
	"5666/tcp": "nrpe", "5800/tcp": "vnc-http", "5900/tcp": "vnc",
	"6000/tcp": "X11", "6001/tcp": "X11:1", "6646/tcp": "unknown",
	"7070/tcp": "realserver", "8000/tcp": "http-alt", "8008/tcp": "http",
	"8009/tcp": "ajp13", "8080/tcp": "http-proxy", "8081/tcp": "blackice-icecap",
	"8443/tcp": "https-alt", "8888/tcp": "sun-answerbook",
	"9100/tcp": "jetdirect", "9999/tcp": "abyss", "10000/tcp": "snet-sensor-mgmt",
	"32768/tcp": "filenet-tms", "49152/tcp": "unknown", "49153/tcp": "unknown",
	"49154/tcp": "unknown", "49155/tcp": "unknown", "49156/tcp": "unknown",
	"49157/tcp": "unknown",
}
