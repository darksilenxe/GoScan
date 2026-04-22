// Package port parses Nmap-style port specifications.
package port

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	MinPort = 1
	MaxPort = 65535
)

// CommonPorts is the list of ports scanned when no -p flag is given (top 1000).
var CommonPorts = buildCommonPorts()

func buildCommonPorts() []int {
	// Nmap's default top-1000 TCP ports (abridged to the top 1024 for simplicity)
	top := []int{
		80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
		143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
		1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
		10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
		26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
		5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
		2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
		544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
		7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
		6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
	}
	// fill remaining up to 1024
	set := make(map[int]bool, len(top))
	for _, p := range top {
		set[p] = true
	}
	for p := 1; p <= 1024; p++ {
		if !set[p] {
			top = append(top, p)
		}
	}
	return top
}

// Parse parses an Nmap-style port specification string.
// Supported formats:
//
//	"80"          single port
//	"80,443"      comma-separated
//	"80-100"      range
//	"1-1024,8080" combination
//	"-"           all ports 1-65535
func Parse(spec string) ([]int, error) {
	if spec == "-" {
		all := make([]int, MaxPort)
		for i := range all {
			all[i] = i + 1
		}
		return all, nil
	}

	seen := make(map[int]bool)
	var ports []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			sub := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(sub[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q in %q", sub[0], spec)
			}
			end, err := strconv.Atoi(sub[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q in %q", sub[1], spec)
			}
			if start < MinPort || end > MaxPort || start > end {
				return nil, fmt.Errorf("invalid range %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			if p < MinPort || p > MaxPort {
				return nil, fmt.Errorf("port %d out of range", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}
