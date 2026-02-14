# Network Port Scanner

A fast, multi-threaded Python port scanner designed for security operations and network asset discovery. Built for security professionals conducting authorized security assessments.

## Features

- Multi-threaded scanning - Fast concurrent scanning using ThreadPoolExecutor
- Service fingerprinting - Banner grabbing identifies running services and versions
- CIDR notation support - Discover assets across entire network ranges
- Configurable performance - Adjust thread count based on network conditions
- JSON export - Integrate results with SIEM or asset management tools
- Clean CLI - Straightforward command-line interface for quick assessments

## Requirements

- Python 3.7 or higher
- No external dependencies (uses Python standard library only)

## Installation
```bash
git clone https://github.com/johnnenna6/Port-Scanner.git
cd Port-Scanner
```

## Usage

**Discover assets on internal subnet:**
```bash
python3 scanner.py -t 192.168.1.0/24
```

**Scan common service ports:**
```bash
python3 scanner.py -t 10.0.0.0/24 -p 22,80,443,3389,445,3306
```

**Export findings for SIEM ingestion:**
```bash
python3 scanner.py -t 192.168.1.0/24 -o asset_discovery.json
```

**Adjust scan speed for production networks:**
```bash
python3 scanner.py -t 10.0.0.0/16 -w 50
```

**Display help:**
```bash
python3 scanner.py -h
```

### Command-Line Options
```
-t, --target    Target network in CIDR notation (required)
-p, --ports     Comma-separated ports to scan (default: 22,80,443)
-w, --workers   Maximum concurrent workers (default: 100)
-o, --output    Save results to JSON file for further analysis
```

## Example Output
```
Starting scan on 192.168.1.0/24

192.168.1.10:
  Port: 22 - Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
  Port: 80 - Banner: Apache/2.4.41 (Ubuntu)

192.168.1.25:
  Port: 3389 - Open (No banner)
  Port: 445 - Open (No banner)

192.168.1.50:
  Port: 22 - Banner: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
  Port: 3306 - Open (No banner)

Scan complete - Found 3 host(s)
```

## SOC Use Cases

### Asset Discovery & Inventory
- Identify all active hosts on monitored networks
- Maintain accurate asset inventories for security monitoring
- Detect shadow IT and unauthorized services

### Vulnerability Assessment Support
- Map exposed services for vulnerability correlation
- Identify outdated services requiring patches
- Baseline network services for change detection

### Incident Response
- Quickly identify potentially compromised hosts running unexpected services
- Verify firewall rules and network segmentation during investigations
- Map lateral movement paths in breach scenarios

### Security Monitoring
- Establish service baselines for anomaly detection
- Verify authorized services match security policies
- Detect new services appearing on the network

## How It Works

1. **TCP Connection Testing** - Attempts three-way handshake on each target port using `socket.connect_ex()`
2. **Banner Grabbing** - Reads service identification data via `socket.recv()` on successful connections
3. **Concurrent Execution** - ThreadPoolExecutor manages worker pool for efficient I/O-bound scanning
4. **Result Aggregation** - Thread-safe collection of findings with lock-based synchronization

Banner data helps identify:
- Service types (SSH, HTTP, SMB, MySQL, etc.)
- Software versions (OpenSSH 8.2, Apache 2.4.41)
- Operating system hints (Ubuntu, Debian, Windows)
- Potential vulnerabilities based on version numbers

## Technical Details

- **Threading Model**: `concurrent.futures.ThreadPoolExecutor` for I/O-bound operations
- **Thread Safety**: Lock-based synchronization prevents race conditions
- **Timeout Handling**: 1-second socket timeout for responsive scanning
- **Error Handling**: Validates input and handles network errors gracefully

## Known Limitations

- TCP-only (no UDP scanning capability)
- Banner grabbing effectiveness varies by service type
- Some services require client-initiated data before responding
- Not stealthy - generates logs on target systems

## Legal & Compliance

⚠️ **Authorization Required**

This tool must only be used on networks where you have explicit written authorization. Usage requirements:

- **Internal Networks**: Obtain approval from IT/Security leadership
- **Client Networks**: Require signed authorization letter or SOW
- **Penetration Testing**: Document in rules of engagement

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar laws in other jurisdictions

**The author assumes no liability for unauthorized or malicious use.**

## Project Background

Developed as part of cybersecurity skill development focused on:
- Network reconnaissance fundamentals
- Python socket programming
- Multi-threaded application design
- Security operations workflows

This project demonstrates practical security engineering skills relevant to SOC analyst and security engineer roles.

## Author

**John Nenna**
- [LinkedIn](https://www.linkedin.com/in/john-nenna-ba08a0268)
- [GitHub](https://github.com/johnnenna6)

Built while preparing for Security+ certification and developing practical security operations skills.
