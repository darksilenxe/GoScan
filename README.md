# Disclaimer
I'm not held liable for any misuse of this application and the repo. Please use this responsibility. This should only be used with authorization only.

# GoScan

GoScan is a fast, feature-rich network scanner written in Go, inspired by [Nmap](https://nmap.org/).

## Features

| Feature | Flag | Notes |
|---|---|---|
| TCP connect scan | *(default)* / `-sT` | No root required |
| TCP SYN scan | `-sS` | Requires root / `CAP_NET_RAW`; falls back to connect scan |
| UDP scan | `-sU` | Requires root / `CAP_NET_RAW` |
| Ping-only discovery | `-sn` | ICMP echo; falls back to TCP probe |
| Skip ping | `-Pn` | Treat all hosts as up |
| Port specification | `-p` | `22`, `1-1024`, `22,80,443`, `-` (all ports) |
| Timing templates | `-T0`…`-T5` | paranoid → insane |
| Service detection | `-sV` | Banner grab + service name lookup |
| OS fingerprinting | `-O` | TTL-based + banner heuristics |
| Nmap script engine (NSE) | `--script`, `--script-args` | Runs Nmap NSE scripts (including `all`) via installed `nmap` |
| Normal output | stdout / `-oN` | Nmap-style human-readable |
| XML output | `-oX` | Nmap-compatible XML schema |
| JSON output | `-oJ` | Machine-readable JSON |
| Grepable output | `-oG` | One line per host |
| Verbose | `-v` | Show closed/filtered ports and banners |

## Installation

```bash
git clone https://github.com/darksilenxe/GoScan.git
cd GoScan
go build -o goscan .
```

Or install directly:

```bash
go install github.com/darksilenxe/goscan@latest
```

## Usage

```
goscan [flags] <target> [target...]
```

### Target formats

| Format | Example |
|---|---|
| Single IP | `192.168.1.1` |
| CIDR range | `192.168.1.0/24` |
| Octet range | `192.168.1.1-20` |
| Hostname | `scanme.nmap.org` |

### Examples

```bash
# Quick scan of common ports (default top-1000)
goscan 192.168.1.1

# SYN scan with service detection (requires root)
sudo goscan -sS -sV 192.168.1.0/24

# Scan specific ports with OS detection
goscan -p 22,80,443,8080 -O scanme.nmap.org

# Run all NSE scripts through nmap (requires nmap installed)
goscan --script all -p 22,80,443 scanme.nmap.org

# Full port scan, aggressive timing
goscan -p- -T4 10.0.0.1

# Ping sweep — discover live hosts without port scanning
goscan -sn 10.0.0.0/24

# UDP scan (requires root)
sudo goscan -sU -p 53,67,123,161 192.168.1.1

# Save output in multiple formats
goscan -sV -oN output.txt -oX output.xml -oJ output.json 192.168.1.0/24

# Treat host as up (skip ping) and scan verbosely
goscan -Pn -v -p 1-1024 192.168.1.1
```

### All flags

```
  -sT           TCP connect scan (default, no root required)
  -sS           TCP SYN scan (requires root/CAP_NET_RAW)
  -sU           UDP scan (requires root/CAP_NET_RAW)
  -sn           Ping scan only — no port scanning
  -Pn           Skip ping, treat all hosts as up
  -p <ports>    Port specification (22 | 1-1024 | 22,80,443 | -)
  -T <0-5>      Timing template (default: 3/normal)
  -sV           Probe open ports to determine service/version
  -O            Enable OS detection
  --script      Run Nmap NSE scripts (e.g. default,vuln,http-*)
  --script-args Arguments passed to NSE scripts (name=value pairs)
  -v            Verbose output (show closed/filtered ports, banners)
  -oN <file>    Save normal output to file
  -oX <file>    Save XML output to file
  -oJ <file>    Save JSON output to file
  -oG <file>    Save grepable output to file
  --min-parallelism <n>   Override port goroutine parallelism
  --host-timeout <ms>     Override per-host timeout (milliseconds)
```

### Timing templates

| Level | Name | Timeout | Parallelism |
|---|---|---|---|
| `-T0` | paranoid | 5 min | 1 |
| `-T1` | sneaky | 15 s | 1 |
| `-T2` | polite | 1 s | 1 |
| `-T3` | normal | 1 s | 100 |
| `-T4` | aggressive | 500 ms | 300 |
| `-T5` | insane | 250 ms | 500 |

## Building & Testing

```bash
go build -o goscan .
go test ./...
```

## Notes

- SYN scan (`-sS`) and ICMP ping require root privileges or `CAP_NET_RAW`.  
  GoScan automatically falls back to TCP connect scan when raw sockets are unavailable.
- UDP scanning is inherently unreliable; open ports may not respond.  
  Ports that return no response are marked `open|filtered`.
- OS detection is heuristic (TTL value + banner keywords) and less precise than Nmap's
  full TCP/IP stack fingerprinting.
- NSE support depends on a local `nmap` binary. GoScan executes Nmap scripts by
  shelling out to `nmap --script ...`, so all installed NSE scripts are available
  (including `--script all`).

## License

MIT
