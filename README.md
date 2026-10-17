<<<<<<< HEAD
# atalaya-recon
Atalaya-recon is an OSINT reconnaissance tool that allows you to recover intelligence information about IP addresses by simultaneously querying multiple external providers
=======
# Atalaya-Recon

**OSINT Reconnaissance Tool** - Gather IP intelligence with multiple providers.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Overview

Atalaya-Recon is a powerful OSINT tool designed to gather comprehensive intelligence information about IP addresses. It queries multiple external providers in parallel to collect geolocation, reputation, threat intelligence, WHOIS records, and more.

## Features

- **Multi-Provider OSINT**: Query multiple threat intelligence and OSINT sources simultaneously
- **Nmap Integration**: Port scanning with configurable modes (silent/aggressive/basic/custom)
- **Parallel Execution**: All provider queries run concurrently for speed
- **Structured Output**: Clean, formatted table output or JSON for automation
- **API Key Management**: Clear indicators when providers need configuration

## Providers

| Provider | Description | API Key Required |
|----------|-------------|------------------|
| **Shodan** | Devices and vulnerabilities search engine | Yes (Free tier available) |
| **VirusTotal** | IP/URL reputation analysis | Yes (Free tier available) |
| **AlienVault OTX** | Collaborative threat intelligence | Yes (Free) |
| **AbuseIPDB** | Malicious IP reports | Yes (Free tier available) |
| **RDAP** | WHOIS registration info (modern standard) | No |
| **ip-api** | Geolocation data | No |
| **ifconfig.me** | Your public IP info | No |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/atalaya-recon.git
cd atalaya-recon
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Nmap (Optional - Required for `--nmap-*` options)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from https://nmap.org/download.html

### 5. Configure API Keys (Optional)

Create a `.env` file in the project root:

```env
APP_NAME=ATALAYA RECON
APP_VERSION=1.0
APP_DEBUG=false

# API Keys (obtain from respective services)
APIKEY_SHODAN=your_shodan_api_key
APIKEY_IP_VIRUS_TOTAL=your_virustotal_api_key
APIKEY_OTX=your_alienvault_otx_api_key
APIKEY_IP_ABUSE_DB=your_abuseipdb_api_key
```

**Get your API keys:**

| Provider | Free Tier | Registration Link |
|----------|-----------|------------------|
| Shodan | Yes | https://account.shodan.io/register |
| VirusTotal | Yes | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | Yes | https://otx.alienvault.com/api |
| AbuseIPDB | Yes | https://www.abuseipdb.com/account/api |

> **Note**: Some providers work without API keys (RDAP, ip-api, ifconfig.me). API keys are required for Shodan, VirusTotal, AlienVault OTX, and AbuseIPDB for full functionality.

## Usage

### Basic Examples

```bash
# Show this help
python atalaya-recon.py --help

# List all available providers
python atalaya-recon.py --list-providers

# Get your public IP address
python atalaya-recon.py --my-ip

# Scan a single target with geolocation
python atalaya-recon.py -t 8.8.8.8 -p geolocation

# Full reconnaissance with all providers
python atalaya-recon.py -t 8.8.8.8 -p all

# Nmap silent scan (stealth mode) - requires nmap installed
python atalaya-recon.py -t 192.168.1.1 --nmap-mode silent --nmap-ports 22,80,443

# Nmap aggressive scan with vulnerability scripts - requires nmap installed
python atalaya-recon.py -t 8.8.8.8 --nmap-mode aggressive -p shodan
```

### Command Options

| Option | Description |
|--------|-------------|
| `-t, --target <IP>` | Target IP address to analyze |
| `-p, --providers <PROV>` | Providers to use (space-separated or 'all') |
| `--nmap-mode <MODE>` | Nmap scan mode: silent, aggressive, basic, custom |
| `--nmap-ports <PORTS>` | Ports for nmap (e.g., '22,80,443' or '1-1000') |
| `--nmap-scripts <SCRIPTS>` | NSE scripts (comma-separated) |
| `--my-ip` | Get your public IP address |
| `-l, --list-providers` | List all available providers |
| `-o, --output <FILE>` | Save output to file |
| `--json` | Output in JSON format |
| `-q, --quiet` | Suppress informational messages |

### Nmap Modes

| Mode | Description |
|------|-------------|
| **silent** | Stealth scan - slow, quiet, minimal IDS detection |
| **aggressive** | Full scan with OS detection, version detection, and vulnerability scripts |
| **basic** | Balanced - good information at moderate speed |
| **custom** | User-defined ports and scripts |

> **Important**: The `--nmap-*` options require Nmap to be installed on your system. See installation instructions above.

## Output Examples

### Table Format (Default)
```
================================================================================
                         ATALAYA-RECON: 8.8.8.8
================================================================================

SOURCE IP (Your Public IP)
--------------------------
  Your IP: 181.42.130.127

================================================================================
                    GEOLOCATION - IP-API - geolocation data
================================================================================
  Country: United States (US)
  Region: Virginia (VA)
  City: Ashburn
  ISP: Google LLC
  ...
```

### JSON Format
```bash
python atalaya-recon.py -t 8.8.8.8 -p all --json
```

## Project Structure

```
atalaya-recon/
├── atalaya-recon.py      # Main CLI entry point
├── modules/
│   ├── settings.py       # Configuration and logging
│   └── nmap_mod.py       # Nmap integration
├── providers/
│   ├── base.py           # Base provider class
│   ├── shodan.py         # Shodan integration
│   ├── virustotal.py      # VirusTotal integration
│   ├── alienvault_otx.py # AlienVault OTX integration
│   ├── ip_abuse_db.py    # AbuseIPDB integration
│   ├── rdap_lookup.py    # RDAP/WHOIS integration
│   ├── ip_api_geolocation.py  # ip-api.com integration
│   └── ifconfig_me.py    # ifconfig.me integration
├── requirements.txt      # Python dependencies
├── .env.example          # Example environment file
└── .gitignore            # Git ignore file
```

## Security & Legal Notice

This tool is intended for **legitimate security research and reconnaissance** only. Please ensure you have proper authorization before scanning any target. The developers are not responsible for misuse of this tool.

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
>>>>>>> 2e382a2 (First commit: Atalaya Recon)
