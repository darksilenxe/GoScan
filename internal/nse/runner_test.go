package nse

import (
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	got := buildArgs("scanme.nmap.org", []int{22, 80, 443}, "default,vuln", "unsafe=1")
	want := []string{
		"-Pn", "-n", "--script", "default,vuln",
		"-p", "22,80,443",
		"--script-args", "unsafe=1",
		"scanme.nmap.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestBuildArgsWithoutPortsOrScriptArgs(t *testing.T) {
	got := buildArgs("192.168.1.1", nil, "all", "")
	want := []string{
		"-Pn", "-n", "--script", "all", "192.168.1.1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestJoinPorts(t *testing.T) {
	if got, want := joinPorts([]int{53, 67, 123}), "53,67,123"; got != want {
		t.Fatalf("expected %q got %q", want, got)
	}
}
