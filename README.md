# VulnX - Advanced Vulnerability Scanner


A comprehensive, multi-tool vulnerability scanner for web applications and networks. VulnX integrates the best security tools into a unified, user-friendly interface with professional reporting capabilities.

## Join Our Community

**WhatsApp Channel: [Exploit Lab](https://whatsapp.com/channel/0029VaepfcHBVJkzG6I1y80b)**

Stay updated with:

- Latest security vulnerabilities

- Tool updates and new features

- Security research and findings

- Community discussions

- Expert tips and techniques

## Features

- **🔧 Multi-Tool Integration**: Nmap, Nikto, SQLMap, OWASP ZAP, and custom fuzzing

- **🎯 Flexible Scanning**: Quick, deep, and full scan profiles

- **📊 Professional Reporting**: JSON, CSV, and text output formats

- **⚡ Rate Limiting**: Avoid overwhelming targets

- **🔌 Plugin System**: Extensible architecture for custom tools

- **🎨 Rich Interface**: Colorized output with progress indicators

- **🔒 Security Focused**: Safe modes and scope control

## Installation

### Prerequisites

```bash
# Ensure Python 3.8+ is installed
python3 --version

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3-pip nmap nikto sqlmap zaproxy
```

Quick Install

```bash
# Clone repository
git clone https://github.com/expl0itlab/vulnx.git
cd vulnx

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

Docker Installation

```bash
# Build from source
docker build -t vulnx .

# Or use pre-built image
docker pull expl0itlab/vulnx:latest
```

Usage

Basic Scan

```bash
vulnx scan --target https://example.com
```

Deep Scan with Custom Output

```bash
vulnx scan --target 192.168.1.1 --profile deep --output json --output-file scan_results
```

Full Scan with ZAP Integration

```bash
vulnx scan --target https://testapp.com --profile full --zap-host localhost --zap-port 8080
```

Endpoint Fuzzing

```bash
vulnx fuzz --target https://example.com --threads 20 --wordlist paths.txt
```

Show Available Plugins

```bash
vulnx plugins
```

Scan Profiles

Quick Profile

· Basic network mapping with Nmap
· Web server analysis with Nikto
· Fast execution, minimal footprint

```bash
vulnx scan --target example.com --profile quick
```

Deep Profile

· Comprehensive port scanning

· Web vulnerability assessment

· SQL injection testing

· Endpoint discovery

```bash
vulnx scan --target example.com --profile deep
```

Full Profile

· Complete network assessment

· Advanced web application testing with ZAP

· Comprehensive fuzzing

· In-depth SQL injection analysis

```bash
vulnx scan --target example.com --profile full --zap-host localhost
```

OWASP ZAP Setup

For full web application scanning capabilities, set up OWASP ZAP:

1. Install ZAP

```bash
# On Kali Linux
sudo apt update && sudo apt install zaproxy

# On Ubuntu/Debian
sudo apt install zaproxy

# Using Docker
docker pull owasp/zap2docker-stable
```

2. Start ZAP with API

```bash
# Desktop version - enable API in GUI
zaproxy

# Headless version
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true

# Docker version
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

3. Configure VulnX with ZAP

```bash
# Scan with custom ZAP configuration
vulnx scan --target https://example.com --profile full --zap-host localhost --zap-port 8080 --zap-api-key your-api-key
```

Output Formats

JSON Output

```bash
vulnx scan --target example.com --output json --output-file results
```

```json
{
  "tool": "Nmap",
  "severity": "info",
  "description": "Open port: 80 - http",
  "details": {
    "port": "80",
    "state": "open",
    "service": "http"
  },
  "timestamp": "2030-01-15T10:30:00"
}
```

CSV Output

```bash
vulnx scan --target example.com --output csv --output-file results
```

Text Output

```bash
vulnx scan --target example.com --output txt --output-file results
```

Plugin System

VulnX supports custom plugins for extended functionality:

Create a Custom Plugin

```python
from vulnx.plugins import BasePlugin

class CustomScanner(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "CustomScanner"
        self.description = "My custom vulnerability scanner"
    
    def scan(self, target: str, **kwargs):
        # Your scanning logic here
        return [{
            "tool": self.name,
            "severity": "medium",
            "description": "Custom vulnerability found",
            "details": {"target": target}
        }]
```

Configuration

Configuration File

Create ~/.vulnx/config.yaml:

```yaml
default:
  scan_profile: quick
  output_format: json
  rate_limit: 0.1
  timeout: 30

profiles:
  quick:
    tools: ["nmap", "nikto"]
    nmap_scan: "quick"
    
  deep:
    tools: ["nmap", "nikto", "fuzzer", "sqlmap"]
    nmap_scan: "deep"
    sqlmap_level: 2
    
  full:
    tools: ["nmap", "nikto", "fuzzer", "sqlmap", "zap"]
    nmap_scan: "deep"
    sqlmap_level: 3

zap:
  host: localhost
  port: 8080
  api_key: null
```

Environment Variables

```bash
export VULNX_ZAP_HOST=localhost
export VULNX_ZAP_PORT=8080
export VULNX_OUTPUT_FORMAT=json
```

Security Considerations

Authorized Usage

· Only scan targets you own or have explicit permission to test
· Respect robots.txt and security headers
· Follow responsible disclosure practices

Rate Limiting

```bash
# Add delay between requests
vulnx scan --target example.com --rate-limit 0.5

# Limit concurrent threads
vulnx fuzz --target example.com --threads 5
```

Safe Mode

```bash
# Disable potentially destructive tests
vulnx scan --target example.com --safe-mode
```

Troubleshooting

Common Issues

ZAP Connection Failed

```bash
# Check if ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Start ZAP if not running
zap.sh -daemon -host 127.0.0.1 -port 8080
```

Tool Not Found

```bash
# Install missing tools
sudo apt install nmap nikto sqlmap

# Or specify which tools to use
vulnx scan --target example.com --tools nmap,nikto
```

Permission Issues

```bash
# Run with sudo if needed for certain scans
sudo vulnx scan --target example.com --profile deep
```

Debug Mode

```bash
# Enable verbose output for debugging
vulnx scan --target example.com --verbose
```

Contributing

We welcome contributions from the security community!

How to Contribute

1. Fork the repository

2. Create a feature branch: git checkout -b feature/amazing-feature

3. Commit your changes: git commit -m 'Add amazing feature'

4. Push to the branch: git push origin feature/amazing-feature

5. Open a Pull Request

Development Setup

```bash
# Set up development environment
git clone https://github.com/exploitarium/vulnx.git
cd vulnx
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
pip install -r requirements.txt
pip install -e .
```

Code Style

· Follow PEP 8 guidelines

· Use type hints

· Include docstrings for all functions

· Write tests for new features

Changelog

v1.0.0

· Initial release with multi-tool integration

· Real OWASP ZAP API support

· Professional reporting capabilities

· Plugin system foundation

Community

· WhatsApp Channel: Exploit Lab
· Issues: GitHub Issues
· Discussions: GitHub Discussions

License

MIT License - see LICENSE file for details.

⚠️ Disclaimer

This tool is designed for educational purposes and authorized security testing only.

Important:

· Always obtain proper authorization before scanning any systems

· Comply with all applicable laws and regulations

· Use responsibly and ethically

· The developers are not responsible for misuse or damage caused by this tool

---

Star us on GitHub if you find this tool useful!

Don't forget to join our WhatsApp channel: Exploit Lab

Stay Secure, Scan Responsibly
