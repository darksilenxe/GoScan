package output_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/darksilenxe/goscan/internal/output"
	"github.com/darksilenxe/goscan/internal/scanner"
)

func makeHost(ip string, up bool, ports []scanner.PortResult) scanner.HostResult {
	return scanner.HostResult{
		IP:        ip,
		IsUp:      up,
		Ports:     ports,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
}

func TestNormalOutputUpHost(t *testing.T) {
	var buf bytes.Buffer
	w := output.NewWriter(&buf, output.FormatNormal)
	host := makeHost("192.168.1.1", true, []scanner.PortResult{
		{Port: 80, Proto: "tcp", State: scanner.StateOpen, Service: "http"},
		{Port: 22, Proto: "tcp", State: scanner.StateClosed, Service: "ssh"},
	})
	w.WriteHostResult(host, false)
	out := buf.String()
	if !strings.Contains(out, "192.168.1.1") {
		t.Error("expected IP in output")
	}
	if !strings.Contains(out, "80/tcp") {
		t.Error("expected port 80 in output")
	}
	if !strings.Contains(out, "open") {
		t.Error("expected 'open' in output")
	}
}

func TestNormalOutputDownHost(t *testing.T) {
	var buf bytes.Buffer
	w := output.NewWriter(&buf, output.FormatNormal)
	host := makeHost("10.0.0.1", false, nil)
	w.WriteHostResult(host, true)
	out := buf.String()
	if !strings.Contains(out, "down") {
		t.Error("expected 'down' in verbose output for down host")
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	w := output.NewWriter(&buf, output.FormatJSON)
	results := []scanner.HostResult{
		makeHost("1.2.3.4", true, []scanner.PortResult{
			{Port: 443, Proto: "tcp", State: scanner.StateOpen, Service: "https"},
		}),
	}
	w.WriteFooter(results, 2*time.Second)
	out := buf.String()
	if !strings.Contains(out, `"ip"`) {
		t.Error("expected 'ip' field in JSON output")
	}
	if !strings.Contains(out, "1.2.3.4") {
		t.Error("expected IP in JSON output")
	}
	if !strings.Contains(out, "elapsed_seconds") {
		t.Error("expected elapsed_seconds in JSON output")
	}
}

func TestXMLOutput(t *testing.T) {
	var buf bytes.Buffer
	w := output.NewWriter(&buf, output.FormatXML)
	results := []scanner.HostResult{
		makeHost("5.6.7.8", true, []scanner.PortResult{
			{Port: 22, Proto: "tcp", State: scanner.StateOpen, Service: "ssh"},
		}),
	}
	w.WriteFooter(results, time.Second)
	out := buf.String()
	if !strings.Contains(out, "<nmaprun") {
		t.Error("expected XML root element")
	}
	if !strings.Contains(out, "5.6.7.8") {
		t.Error("expected IP in XML output")
	}
}

func TestGrepableOutput(t *testing.T) {
	var buf bytes.Buffer
	w := output.NewWriter(&buf, output.FormatGrepable)
	host := makeHost("172.16.0.1", true, []scanner.PortResult{
		{Port: 80, Proto: "tcp", State: scanner.StateOpen, Service: "http"},
	})
	w.WriteHostResult(host, false)
	out := buf.String()
	if !strings.Contains(out, "172.16.0.1") {
		t.Error("expected IP in grepable output")
	}
	if !strings.Contains(out, "80/open/tcp/http") {
		t.Error("expected port info in grepable output")
	}
}

func TestWriteCompletionArt(t *testing.T) {
	var buf bytes.Buffer
	output.WriteCompletionArt(&buf)

	out := buf.String()
	if !strings.Contains(out, "GoScan is starting!") {
		t.Error("expected startup message in completion art")
	}
	if !strings.Contains(out, ",_---~~~~~----._") {
		t.Error("expected gopher art in output")
	}
}
