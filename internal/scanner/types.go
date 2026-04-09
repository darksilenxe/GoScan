// Package scanner implements Nmap-style host/port scanning.
package scanner

import (
	"time"
)

// ScanType identifies the type of port scan to perform.
type ScanType string

const (
	ScanTCP  ScanType = "TCP"  // TCP connect scan (-sT)
	ScanSYN  ScanType = "SYN"  // TCP SYN scan (-sS, requires root)
	ScanUDP  ScanType = "UDP"  // UDP scan (-sU, requires root)
	ScanPing ScanType = "Ping" // Host discovery only (-sn)
)

// PortState represents the observed state of a scanned port.
type PortState string

const (
	StateOpen             PortState = "open"
	StateClosed           PortState = "closed"
	StateFiltered         PortState = "filtered"
	StateOpenFiltered     PortState = "open|filtered"
	StateClosedFiltered   PortState = "closed|filtered"
)

// PortResult contains the scan result for one port.
type PortResult struct {
	Port     int
	Proto    string
	State    PortState
	Service  string
	Version  string // populated when -sV is used
	Banner   string // raw banner (first line)
}

// HostResult contains all results for a single host.
type HostResult struct {
	IP        string
	Hostname  string
	IsUp      bool
	OS        string
	OSDetails string
	TTL       int
	Latency   time.Duration
	Ports     []PortResult
	StartTime time.Time
	EndTime   time.Time
}

// Options controls scan behaviour.
type Options struct {
	ScanType      ScanType
	Ports         []int
	Timeout       time.Duration   // per-port connect timeout
	HostTimeout   time.Duration   // max time per host
	Parallelism   int             // number of concurrent goroutines per host
	MaxHostConc   int             // concurrent hosts
	ServiceDetect bool            // -sV
	OSDetect      bool            // -O
	PingScan      bool            // -sn (skip port scanning)
	SkipPing      bool            // -Pn (treat all hosts as up)
	Verbose       bool
}

// TimingTemplate maps -T0…-T5 to sane defaults.
func TimingTemplate(level int) (timeout, hostTimeout time.Duration, parallelism int) {
	switch level {
	case 0: // paranoid
		return 5 * time.Minute, 30 * time.Minute, 1
	case 1: // sneaky
		return 15 * time.Second, 15 * time.Minute, 1
	case 2: // polite
		return 1 * time.Second, 5 * time.Minute, 1
	case 3: // normal (default)
		return 1 * time.Second, 5 * time.Minute, 100
	case 4: // aggressive
		return 500 * time.Millisecond, 2 * time.Minute, 300
	case 5: // insane
		return 250 * time.Millisecond, 45 * time.Second, 500
	default:
		return 1 * time.Second, 5 * time.Minute, 100
	}
}
