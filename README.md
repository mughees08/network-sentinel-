# Network Sentinel
### Offline Network Traffic Analysis & Threat-Hunting Toolkit

Network Sentinel is a portfolio-ready Python project for analyzing **packet-capture files you own or are authorized to inspect**. It summarizes traffic, identifies common protocols, extracts DNS/HTTP metadata, and flags a few explainable traffic patterns for analyst review.

> **Scope:** This tool analyzes existing PCAP/PCAPNG files offline. It does not scan networks, exploit hosts, or prove that activity is malicious. Alerts are heuristics and require human validation.

## Features
- PCAP/PCAPNG offline analysis using Scapy
- Protocol distribution and packet/byte totals
- Top source and destination IPs
- DNS query metadata and HTTP host metadata (when visible)
- Heuristic alerts for possible SYN bursts, unusually high DNS query volume, and cleartext HTTP
- JSON and CSV report export
- Unit tests for alert logic
- No external services or API keys required

## Requirements
- Python 3.10+
- Scapy 2.5+

## Quick start

### 1. Create a virtual environment
```bash
python -m venv .venv
```
Activate it:
- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

### 2. Install dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Analyze an authorized capture
```bash
python -m network_sentinel.cli path/to/capture.pcap --out reports
```
For PCAPNG:
```bash
python -m network_sentinel.cli path/to/capture.pcapng --out reports
```

The tool creates `report.json` and `protocols.csv` in the output directory.

### 4. See command options
```bash
python -m network_sentinel.cli --help
```

## Example report
A report includes:
- Capture filename, packet count, total bytes
- Protocol counts
- Top talkers
- DNS query names and HTTP hostnames when those fields are available
- Analyst-review alerts with severity, evidence, and explanation

## Limitations
- Encrypted traffic generally hides application payload details.
- DNS over HTTPS, packet loss, capture filters, and incomplete captures affect findings.
- SYN-burst detection is a simple threshold heuristic, not a definitive port-scan detector.
- HTTP metadata is only visible when the capture contains unencrypted HTTP.
- Thresholds are intentionally simple and should be tuned for your environment.

## Safe practice
Use a sample capture, your own lab, or traffic you have explicit permission to analyze. Do not upload captures containing personal, business, or confidential data to a public repository. Never commit credentials, private keys, or sensitive PCAP files.

## Project structure
```text
network-sentinel/
├── network_sentinel/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── cli.py
│   └── models.py
├── tests/
│   └── test_analyzer.py
├── reports/
│   └── .gitkeep
├── .gitignore
├── LICENSE
├── requirements.txt
└── pyproject.toml
```

## Future improvements
- Baseline-aware anomaly detection
- Configurable YAML thresholds
- HTML dashboard
- IPv6-focused enrichment
- CI workflow and signed release artifacts

## Portfolio description
**Network Sentinel — Offline PCAP Analysis & Threat Hunting**
Built a Python-based packet-capture analyzer that summarizes network protocols, ranks top talkers, extracts visible DNS/HTTP metadata, and produces JSON/CSV reports with explainable heuristic alerts. Designed for authorized offline analysis with documented limitations and unit tests.
