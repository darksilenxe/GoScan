// Package cmd implements the GoScan command-line interface.
package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/darksilenxe/goscan/internal/nse"
	"github.com/darksilenxe/goscan/internal/output"
	"github.com/darksilenxe/goscan/internal/port"
	"github.com/darksilenxe/goscan/internal/scanner"
	"github.com/darksilenxe/goscan/internal/target"
)

var (
	// Scan type flags
	flagScanTCP  bool
	flagScanSYN  bool
	flagScanUDP  bool
	flagPingScan bool
	flagSkipPing bool

	// Target/port flags
	flagPorts string

	// Timing
	flagTiming int

	// Detection
	flagServiceDetect bool
	flagOSDetect      bool
	flagScripts       string
	flagScriptArgs    string

	// Output
	flagVerbose    bool
	flagOutputNorm string
	flagOutputXML  string
	flagOutputJSON string
	flagOutputGrep string

	// Advanced
	flagParallelism int
	flagTimeout     int // milliseconds
)

// rootCmd is the root GoScan command.
var rootCmd = &cobra.Command{
	Use:   "goscan [flags] <target> [target...]",
	Short: "GoScan — an Nmap-compatible network scanner written in Go",
	Long: `GoScan is a fast, Nmap-inspired network scanner written in Go.

Targets can be:
  • Single IP:        192.168.1.1
  • CIDR range:       192.168.1.0/24
  • Octet range:      192.168.1.1-10
  • Hostname:         example.com

Examples:
  goscan 192.168.1.1
  goscan -sS -p 22,80,443 192.168.1.0/24
  goscan -sV -O -T4 scanme.nmap.org
  goscan -sn 10.0.0.0/8
  goscan -p- --min-parallelism 500 -T5 192.168.0.1`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

// Execute is the entry point called by main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Scan type
	rootCmd.Flags().BoolVarP(&flagScanTCP, "sT", "", false, "TCP connect scan (default, no root required)")
	rootCmd.Flags().BoolVarP(&flagScanSYN, "sS", "", false, "TCP SYN scan (requires root/CAP_NET_RAW)")
	rootCmd.Flags().BoolVarP(&flagScanUDP, "sU", "", false, "UDP scan (requires root/CAP_NET_RAW)")
	rootCmd.Flags().BoolVarP(&flagPingScan, "sn", "", false, "Ping scan only — no port scanning")
	rootCmd.Flags().BoolVarP(&flagSkipPing, "Pn", "", false, "Treat all hosts as up (skip ping)")

	// Ports
	rootCmd.Flags().StringVarP(&flagPorts, "ports", "p", "", "Port specification (e.g. 22,80,443 or 1-1024 or - for all)")

	// Timing
	rootCmd.Flags().IntVarP(&flagTiming, "timing", "T", 3, "Timing template 0-5 (paranoid=0, sneaky=1, polite=2, normal=3, aggressive=4, insane=5)")

	// Detection
	rootCmd.Flags().BoolVarP(&flagServiceDetect, "sV", "", false, "Probe open ports to determine service/version")
	rootCmd.Flags().BoolVarP(&flagOSDetect, "O", "", false, "Enable OS detection")
	rootCmd.Flags().StringVar(&flagScripts, "script", "", "Run Nmap NSE scripts (e.g. default,vuln,http-*)")
	rootCmd.Flags().StringVar(&flagScriptArgs, "script-args", "", "Arguments passed to NSE scripts (name=value pairs)")

	// Output
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVarP(&flagOutputNorm, "oN", "", "", "Save normal output to file")
	rootCmd.Flags().StringVarP(&flagOutputXML, "oX", "", "", "Save XML output to file")
	rootCmd.Flags().StringVarP(&flagOutputJSON, "oJ", "", "", "Save JSON output to file")
	rootCmd.Flags().StringVarP(&flagOutputGrep, "oG", "", "", "Save grepable output to file")

	// Advanced
	rootCmd.Flags().IntVar(&flagParallelism, "min-parallelism", 0, "Minimum parallelism (port goroutines per host)")
	rootCmd.Flags().IntVar(&flagTimeout, "host-timeout", 0, "Host timeout in milliseconds (0 = timing default)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Resolve timing defaults
	tmTimeout, tmHostTimeout, tmParallelism := scanner.TimingTemplate(flagTiming)
	if flagParallelism > 0 {
		tmParallelism = flagParallelism
	}
	if flagTimeout > 0 {
		tmHostTimeout = time.Duration(flagTimeout) * time.Millisecond
	}

	// Determine scan type
	scanType := scanner.ScanTCP
	switch {
	case flagScanSYN:
		scanType = scanner.ScanSYN
	case flagScanUDP:
		scanType = scanner.ScanUDP
	case flagPingScan:
		scanType = scanner.ScanPing
	}

	// Parse ports
	var ports []int
	if flagPingScan {
		ports = nil
	} else if flagPorts != "" {
		var err error
		ports, err = port.Parse(flagPorts)
		if err != nil {
			return fmt.Errorf("invalid port specification: %w", err)
		}
	} else {
		ports = port.CommonPorts
	}

	// Build options
	opts := scanner.Options{
		ScanType:      scanType,
		Ports:         ports,
		Timeout:       tmTimeout,
		HostTimeout:   tmHostTimeout,
		Parallelism:   tmParallelism,
		MaxHostConc:   10,
		ServiceDetect: flagServiceDetect,
		OSDetect:      flagOSDetect,
		PingScan:      flagPingScan,
		SkipPing:      flagSkipPing,
		Verbose:       flagVerbose,
	}

	// Expand targets
	var hosts []string
	for _, arg := range args {
		expanded, err := target.Expand(arg)
		if err != nil {
			return fmt.Errorf("invalid target %q: %w", arg, err)
		}
		hosts = append(hosts, expanded...)
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no valid targets specified")
	}

	output.WriteStartupBanner(os.Stdout)

	// Set up output writers
	writers := buildWriters(cmd)

	argStr := strings.Join(os.Args[1:], " ")
	for _, w := range writers {
		w.WriteHeader(hosts, scanType, argStr)
	}

	// Run scan
	s := scanner.New(opts)
	ctx := context.Background()
	resultCh := s.ScanHosts(ctx, hosts)

	scanStart := time.Now()
	var allResults []scanner.HostResult
	nseRunner := nse.NewRunner("")

	for result := range resultCh {
		if flagScripts != "" && result.IsUp {
			ports := scriptPorts(result)
			scriptOutput, err := nseRunner.RunHostScripts(ctx, result.IP, ports, flagScripts, flagScriptArgs, opts.HostTimeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: NSE scripts %q failed for %s: %v\n", flagScripts, result.IP, err)
			} else {
				result.ScriptOutput = scriptOutput
			}
		}

		allResults = append(allResults, result)
		for _, w := range writers {
			w.WriteHostResult(result, flagVerbose)
		}
	}
	elapsed := time.Since(scanStart)

	for _, w := range writers {
		w.WriteFooter(allResults, elapsed)
	}

	// Close any file writers
	closeWriters()

	return nil
}

var fileWriters []*os.File

func buildWriters(cmd *cobra.Command) []*output.Writer {
	var writers []*output.Writer

	// Always write normal to stdout
	writers = append(writers, output.NewWriter(os.Stdout, output.FormatNormal))

	addFileWriter := func(path string, format output.Format) {
		if path == "" {
			return
		}
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot create output file %q: %v\n", path, err)
			return
		}
		fileWriters = append(fileWriters, f)
		writers = append(writers, output.NewWriter(f, format))
	}

	addFileWriter(flagOutputNorm, output.FormatNormal)
	addFileWriter(flagOutputXML, output.FormatXML)
	addFileWriter(flagOutputJSON, output.FormatJSON)
	addFileWriter(flagOutputGrep, output.FormatGrepable)

	return writers
}

func closeWriters() {
	for _, f := range fileWriters {
		_ = f.Close()
	}
}

func scriptPorts(result scanner.HostResult) []int {
	uniq := map[int]struct{}{}
	for _, p := range result.Ports {
		if p.State != scanner.StateOpen && p.State != scanner.StateOpenFiltered {
			continue
		}
		uniq[p.Port] = struct{}{}
	}
	ports := make([]int, 0, len(uniq))
	for p := range uniq {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
