// Package output formats and writes scan results.
package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darksilenxe/goscan/internal/scanner"
)

// Format identifies the output format.
type Format string

const (
	FormatNormal   Format = "normal"
	FormatXML      Format = "xml"
	FormatJSON     Format = "json"
	FormatGrepable Format = "grepable"
)

// Writer writes scan results to an io.Writer in the given format.
type Writer struct {
	w      io.Writer
	format Format
}

const startupGopher = "\n" +
	"   ,_---~~~~~----._\n" +
	"_,,_,*^____      _____``*g*\\\"*,\n" +
	"/ __/ /'     ^.  /      \\ ^@q   f\n" +
	"[  @f | @))    |  | @))   l  0 _/\n" +
	" \\`/   \\~____ / __ \\_____/    \\\n" +
	"  |           _l__l_           I\n" +
	"  }          [______]          I\n" +
	"  ]            | | |           |\n" +
	"  ]             ~ ~            |\n" +
	"  |                            |\n" +
	"   |   GoScan is starting!    |\n"

// NewWriter creates a new output Writer.
func NewWriter(w io.Writer, format Format) *Writer {
	return &Writer{w: w, format: format}
}

// WriteStartupBanner writes the Go Gopher startup banner.
func WriteStartupBanner(w io.Writer) {
	fmt.Fprint(w, startupGopher)
}

// WriteHeader writes the scan header.
func (wr *Writer) WriteHeader(targets []string, scanType scanner.ScanType, args string) {
	switch wr.format {
	case FormatNormal:
		fmt.Fprintf(wr.w, "\nStarting GoScan ( https://github.com/darksilenxe/GoScan ) at %s\n",
			time.Now().Format("2006-01-02 15:04 MST"))
		fmt.Fprintf(wr.w, "GoScan scan report\n")
	case FormatJSON, FormatXML, FormatGrepable:
		// headers written by WriteResults
	}
}

// WriteHostResult writes a single host result.
func (wr *Writer) WriteHostResult(r scanner.HostResult, verbose bool) {
	switch wr.format {
	case FormatNormal:
		writeNormal(wr.w, r, verbose)
	case FormatGrepable:
		writeGrepable(wr.w, r)
	}
}

// WriteFooter writes the scan summary footer.
func (wr *Writer) WriteFooter(results []scanner.HostResult, elapsed time.Duration) {
	switch wr.format {
	case FormatNormal:
		up := 0
		for _, r := range results {
			if r.IsUp {
				up++
			}
		}
		fmt.Fprintf(wr.w, "\nGoScan done: %d IP address(es) (%d host(s) up) scanned in %.2f seconds\n",
			len(results), up, elapsed.Seconds())
	case FormatJSON:
		writeJSON(wr.w, results, elapsed)
	case FormatXML:
		writeXML(wr.w, results, elapsed)
	}
}

// ─── Normal format ────────────────────────────────────────────────────────────

func writeNormal(w io.Writer, r scanner.HostResult, verbose bool) {
	if !r.IsUp {
		if verbose {
			fmt.Fprintf(w, "\nHost: %s appears to be down.\n", r.IP)
		}
		return
	}

	label := r.IP
	if r.Hostname != "" {
		label = fmt.Sprintf("%s (%s)", r.Hostname, r.IP)
	}
	fmt.Fprintf(w, "\nNmap scan report for %s\n", label)
	fmt.Fprintf(w, "Host is up")
	if r.Latency > 0 {
		fmt.Fprintf(w, " (%.4fs latency)", r.Latency.Seconds())
	}
	fmt.Fprintln(w, ".")

	if r.OS != "" {
		fmt.Fprintf(w, "OS details: %s\n", r.OS)
		if verbose && r.OSDetails != "" {
			fmt.Fprintf(w, "  (%s)\n", r.OSDetails)
		}
	}

	// Collect interesting ports
	var open, closed, filtered int
	var interesting []scanner.PortResult
	for _, p := range r.Ports {
		switch p.State {
		case scanner.StateOpen:
			open++
			interesting = append(interesting, p)
		case scanner.StateClosed:
			closed++
			if verbose {
				interesting = append(interesting, p)
			}
		case scanner.StateFiltered:
			filtered++
			if verbose {
				interesting = append(interesting, p)
			}
		case scanner.StateOpenFiltered:
			interesting = append(interesting, p)
		}
	}

	if len(interesting) == 0 {
		if closed > 0 {
			fmt.Fprintf(w, "All %d scanned ports are closed.\n", closed)
		} else if filtered > 0 {
			fmt.Fprintf(w, "All %d scanned ports are filtered.\n", filtered)
		}
		return
	}

	// Summary line like Nmap: "Not shown: 998 closed ports"
	if !verbose {
		if closed > 0 {
			fmt.Fprintf(w, "Not shown: %d closed port(s)\n", closed)
		}
		if filtered > 0 {
			fmt.Fprintf(w, "Not shown: %d filtered port(s)\n", filtered)
		}
	}

	fmt.Fprintf(w, "%-10s %-12s %s\n", "PORT", "STATE", "SERVICE")
	for _, p := range interesting {
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		svcLine := p.Service
		if p.Version != "" {
			svcLine = fmt.Sprintf("%s  %s", p.Service, p.Version)
		}
		fmt.Fprintf(w, "%-10s %-12s %s\n", portStr, string(p.State), svcLine)
		if verbose && p.Banner != "" {
			fmt.Fprintf(w, "  |_ Banner: %s\n", firstLine(p.Banner))
		}
	}

	if r.ScriptOutput != "" {
		fmt.Fprintln(w, "\nHost script results:")
		for _, line := range strings.Split(r.ScriptOutput, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fmt.Fprintf(w, "|_ %s\n", line)
		}
	}
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
	}
	return s
}

// ─── Grepable format ──────────────────────────────────────────────────────────

func writeGrepable(w io.Writer, r scanner.HostResult) {
	if !r.IsUp {
		return
	}
	var ports []string
	for _, p := range r.Ports {
		if p.State == scanner.StateOpen {
			ports = append(ports, fmt.Sprintf("%d/%s/%s/%s", p.Port, string(p.State), p.Proto, p.Service))
		}
	}
	host := r.IP
	if r.Hostname != "" {
		host = fmt.Sprintf("%s (%s)", r.IP, r.Hostname)
	}
	fmt.Fprintf(w, "Host: %s\tPorts: %s\n", host, strings.Join(ports, ", "))
}

// ─── JSON format ──────────────────────────────────────────────────────────────

type jsonReport struct {
	GeneratedAt string     `json:"generated_at"`
	ElapsedSec  float64    `json:"elapsed_seconds"`
	Hosts       []jsonHost `json:"hosts"`
}

type jsonHost struct {
	IP           string     `json:"ip"`
	Hostname     string     `json:"hostname,omitempty"`
	IsUp         bool       `json:"is_up"`
	OS           string     `json:"os,omitempty"`
	TTL          int        `json:"ttl,omitempty"`
	Latency      string     `json:"latency,omitempty"`
	Ports        []jsonPort `json:"ports,omitempty"`
	ScriptOutput string     `json:"script_output,omitempty"`
}

type jsonPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

func writeJSON(w io.Writer, results []scanner.HostResult, elapsed time.Duration) {
	report := jsonReport{
		GeneratedAt: time.Now().Format(time.RFC3339),
		ElapsedSec:  elapsed.Seconds(),
	}
	for _, r := range results {
		jh := jsonHost{
			IP:           r.IP,
			Hostname:     r.Hostname,
			IsUp:         r.IsUp,
			OS:           r.OS,
			TTL:          r.TTL,
			ScriptOutput: r.ScriptOutput,
		}
		if r.Latency > 0 {
			jh.Latency = r.Latency.String()
		}
		for _, p := range r.Ports {
			jh.Ports = append(jh.Ports, jsonPort{
				Port:    p.Port,
				Proto:   p.Proto,
				State:   string(p.State),
				Service: p.Service,
				Version: p.Version,
				Banner:  p.Banner,
			})
		}
		report.Hosts = append(report.Hosts, jh)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

// ─── XML format ───────────────────────────────────────────────────────────────

type xmlNmapRun struct {
	XMLName    xml.Name  `xml:"nmaprun"`
	Scanner    string    `xml:"scanner,attr"`
	StartStr   string    `xml:"startstr,attr"`
	ElapsedSec string    `xml:"elapsed,attr"`
	Hosts      []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status     xmlStatus      `xml:"status"`
	Address    xmlAddress     `xml:"address"`
	Ports      *xmlPorts      `xml:"ports,omitempty"`
	OS         *xmlOS         `xml:"os,omitempty"`
	HostScript *xmlHostScript `xml:"hostscript,omitempty"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string     `xml:"protocol,attr"`
	Portid   int        `xml:"portid,attr"`
	State    xmlState   `xml:"state"`
	Service  xmlService `xml:"service"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr,omitempty"`
}

type xmlOS struct {
	Match string `xml:"osmatch,attr,omitempty"`
}

type xmlHostScript struct {
	Output string `xml:"output,attr,omitempty"`
}

func writeXML(w io.Writer, results []scanner.HostResult, elapsed time.Duration) {
	run := xmlNmapRun{
		Scanner:    "goscan",
		StartStr:   time.Now().Format(time.RFC1123),
		ElapsedSec: fmt.Sprintf("%.2f", elapsed.Seconds()),
	}
	for _, r := range results {
		state := "down"
		if r.IsUp {
			state = "up"
		}
		xh := xmlHost{
			Status:  xmlStatus{State: state},
			Address: xmlAddress{Addr: r.IP, AddrType: "ipv4"},
		}
		if len(r.Ports) > 0 {
			xh.Ports = &xmlPorts{}
			for _, p := range r.Ports {
				xh.Ports.Ports = append(xh.Ports.Ports, xmlPort{
					Protocol: p.Proto,
					Portid:   p.Port,
					State:    xmlState{State: string(p.State)},
					Service:  xmlService{Name: p.Service, Version: p.Version},
				})
			}
		}
		if r.OS != "" {
			xh.OS = &xmlOS{Match: r.OS}
		}
		if r.ScriptOutput != "" {
			xh.HostScript = &xmlHostScript{Output: r.ScriptOutput}
		}
		run.Hosts = append(run.Hosts, xh)
	}
	fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(run)
	fmt.Fprintln(w)
}
