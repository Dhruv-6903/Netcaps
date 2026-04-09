# NetSentinel — Network Forensics Desktop Tool

NetSentinel is a production-grade network forensics desktop application built with Python and PyQt5. It analyzes PCAP/PCAPNG capture files and live traffic to extract hosts, sessions, credentials, files, DNS events, emails, chat messages, and generate security alerts.

## Features

- **PCAP/PCAPNG Loading** — Single-pass analysis using dpkt; auto-detects format
- **Host Extraction** — OS fingerprinting, MAC/OUI vendor, hostname resolution, GeoIP
- **Session Tracking** — TCP/UDP 5-tuple tracking with payload buffering (10MB cap)
- **Credential Harvesting** — FTP, HTTP Basic/Digest/Form, Telnet, SMTP, POP3, IMAP, LDAP, SNMP, RADIUS
- **DNS Analysis** — Query/response parsing, tunneling detection, DGA entropy scoring, beaconing, fast-flux
- **File Extraction** — HTTP downloads, SMTP attachments, file carving (PDF, JPEG, PNG, ZIP, EXE)
- **Email Parsing** — SMTP/POP3/IMAP with attachment extraction, URL/keyword analysis
- **Chat Parsing** — AIM/OSCAR FLAP/SNAC protocol on port 5190
- **TLS Inspection** — JA3/JA3S fingerprinting, version detection, weak cipher flagging
- **Alert Engine** — 20 built-in detection rules (SYN flood, port scan, data exfil, brute force, etc.)
- **Threat Intelligence** — VirusTotal and AbuseIPDB integration with offline blocklists
- **Live Capture** — scapy AsyncSniffer with BPF filter support
- **Export** — CSV, JSON, HTML dark-theme report, ZIP, Timeline CSV
- **Visualization** — Traffic spike graph, protocol distribution, IP communication map (networkx)

## Technology Stack

| Component | Library |
|-----------|---------|
| GUI | PyQt5 5.15.10 |
| PCAP Parsing | dpkt 1.9.8 |
| Live Capture | scapy 2.5.0 |
| System Info | psutil 5.9.0 |
| GeoIP | geoip2 4.7.0 |
| OUI Lookup | manuf 1.1.5 |
| HTTP Client | httpx 0.27.0 |
| Charts | pyqtgraph 0.13.3 |
| Graph | networkx 3.2 |
| File Magic | python-magic 0.4.27 |
| Packaging | pyinstaller 6.0.0 |

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/Netcaps.git
cd Netcaps/NetSentinel

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Download GeoLite2-City.mmdb from MaxMind
# Place it at assets/GeoLite2-City.mmdb

# Run
python main.py
```

## Configuration

Edit `config/settings.py`:

```python
VT_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_key"
GEOIP_DB_PATH = "assets/GeoLite2-City.mmdb"
MANUF_PATH = "assets/manuf"
OUTPUT_DIR = "output/extracted_files"
REPORTS_DIR = "output/reports"
MASK_PASSWORDS = True  # Mask passwords in UI by default
```

## Usage

### Load a PCAP File
1. Click **📂 Load PCAP** in the toolbar
2. Select your `.pcap` or `.pcapng` file
3. Analysis runs automatically — tabs populate as data is extracted

### Live Capture
1. Select a network interface from the dropdown
2. Optionally enter a BPF filter (e.g., `tcp port 80`)
3. Click **▶ Start Capture**
4. Click **■ Stop Capture** when done

### Export Results
Click **📤 Export ▾** and choose:
- **Export CSV** — Hosts, Sessions, Credentials, Files, DNS, Alerts
- **Export JSON** — Complete analysis data
- **Export HTML Report** — Dark-theme standalone report
- **Export Files ZIP** — Extracted files with manifest
- **Export Timeline CSV** — Chronological event log

## Folder Structure

```
NetSentinel/
  core/           — Analysis engines (no GUI dependencies)
  gui/
    tabs/         — Tab widgets for each data type
    widgets/      — Reusable UI components
    styles/       — QSS dark theme
  output/
    extracted_files/  — Files extracted from PCAP
    reports/          — Exported reports
  assets/         — GeoIP DB, manuf file, icons
  config/         — settings.py, user_prefs.json
  main.py         — Entry point
  requirements.txt
```

## Alert Rules

| # | Rule | Severity |
|---|------|----------|
| 1 | Cleartext Credentials | HIGH |
| 2 | Suspicious DNS Entropy (DGA) | MEDIUM |
| 3 | DNS Subdomain Tunneling | MEDIUM |
| 4 | Port Scan (horizontal) | HIGH |
| 5 | Vertical Port Scan | HIGH |
| 6 | Large File Transfer (>50MB HTTP) | MEDIUM |
| 7 | Non-Standard HTTP Port | LOW |
| 8 | ICMP Flood | MEDIUM |
| 9 | SYN Flood | HIGH |
| 10 | UDP Flood | HIGH |
| 11 | FTP Brute Force | HIGH |
| 12 | SSH Brute Force | HIGH |
| 13 | Known Malicious Hash (VT) | CRITICAL |
| 14 | DNS Beaconing | MEDIUM |
| 15 | Fast-Flux DNS (low TTL) | LOW |
| 16 | DoH Bypass | LOW |
| 17 | Multi-Method Attack | CRITICAL |
| 18 | Data Exfiltration (>100MB outbound) | HIGH |
| 19 | LDAP Cleartext Credentials | HIGH |
| 20 | SMB Lateral Movement | HIGH |

## License

MIT License — see LICENSE file for details.
