# WebScanner

A powerful, customizable CLI-based web security vulnerability scanner inspired by Nikto. Built for modern web security testing with professional-grade features while remaining lightweight and efficient for any average PC.

## Features

- **Comprehensive Security Checks**: Scans for over 100+ common web vulnerabilities
- **Multiple Output Formats**: Console, JSON, XML, and CSV reports
- **Highly Customizable**: Configurable checks, timeouts, and scanning parameters
- **Professional CLI**: Full-featured command-line interface with extensive options
- **Multi-threaded Scanning**: Concurrent checks for improved performance
- **Extensible Plugin System**: Easy to add custom vulnerability checks
- **Lightweight**: No heavy dependencies, runs on any average PC

## Installation

### From Source
```bash
git clone https://github.com/yourusername/webscanner.git
cd webscanner
pip install -r requirements.txt
python setup.py install
```

### Direct Execution
```bash
python -m src.webscanner http://example.com
```

## Usage

### Basic Scan
```bash
webscanner http://example.com
```

### Advanced Usage
```bash
# Scan with custom options
webscanner https://example.com \
  --threads 5 \
  --timeout 10 \
  --delay 0.5 \
  --output json \
  --output-file results.json

# Run specific checks only
webscanner http://example.com --checks header_checks,file_checks

# Verbose output with debug information
webscanner http://example.com -vv

# Scan with custom user agent
webscanner http://example.com --user-agent "My Custom Scanner/1.0"
```

### Command Line Options

```
positional arguments:
  url                   Target URL to scan

optional arguments:
  -h, --help           Show help message and exit
  -o OUTPUT, --output OUTPUT
                       Output format (console, json, xml, csv)
  -f FILE, --output-file FILE
                       Output file path
  -c CHECKS, --checks CHECKS
                       Comma-separated list of checks to run
  -t THREADS, --threads THREADS
                       Number of concurrent threads (default: 10)
  --timeout TIMEOUT    Request timeout in seconds (default: 30)
  --delay DELAY        Delay between requests in seconds (default: 0.1)
  --user-agent UA      Custom User-Agent string
  --proxy PROXY        Proxy URL (http://proxy:port)
  --no-ssl-verify      Skip SSL certificate verification
  -v, --verbose        Increase verbosity
  --quiet              Suppress all output except results
  --version            Show version information
```

## Security Checks

WebScanner performs comprehensive security checks including:

### Header Security Checks
- Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- Weak header configurations
- Server information disclosure

### Server Information Checks
- Server version detection and vulnerability checking
- Technology stack fingerprinting
- Version disclosure in various locations

### File Enumeration
- Common vulnerable files (.env, config files, backups)
- Directory listing vulnerabilities
- Exposed sensitive files

### Miscellaneous Checks
- Dangerous HTTP methods enabled
- Default/test pages exposed
- Cookie security attributes
- SSL/TLS configuration issues

## Output Formats

### Console (Default)
Human-readable colored output with severity-based organization.

### JSON
Structured machine-readable format for integration with other tools.

```json
{
  "scanner": "WebScanner",
  "version": "1.0.0",
  "target_url": "http://example.com",
  "scan_date": "2024-01-01T12:00:00",
  "summary": {
    "total_issues": 15,
    "severity_breakdown": {
      "high": 3,
      "medium": 7,
      "low": 5
    }
  },
  "results": [...]
}
```

### XML
Enterprise-friendly XML format for reporting systems.

### CSV
Spreadsheet-compatible format for data analysis.

## Extending WebScanner

### Adding Custom Checks

Create a new check class inheriting from `BaseCheck`:

```python
from webscanner.checks.base import BaseCheck
from webscanner.core.scanner import ScannerResult

class CustomCheck(BaseCheck):
    def run(self):
        # Your custom logic here
        response = self.make_request('GET', f"{self.base_url}/custom-endpoint")

        if response and 'vulnerable' in response.text:
            self.add_result(
                url=f"{self.base_url}/custom-endpoint",
                check_name='custom_vulnerability',
                severity='high',
                description='Custom vulnerability found',
                evidence='Response contains vulnerable pattern',
                recommendation='Fix the custom vulnerability'
            )

        return self.results
```

Register your check in `webscanner/checks/__init__.py`.

## Configuration

WebScanner supports configuration files for customizing default behavior:

```python
# config.py or .env
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 30
DEFAULT_DELAY = 0.1
CUSTOM_USER_AGENTS = [...]
```

## Performance Considerations

- **Threading**: Adjust `--threads` based on target server capacity
- **Delay**: Use `--delay` to avoid overwhelming the target
- **Timeout**: Set appropriate timeouts for slow networks
- **Checks**: Run specific checks with `--checks` to reduce scan time

## Security & Ethics

- Only scan systems you own or have explicit permission to test
- Respect `robots.txt` and rate limiting
- Use appropriate delays to avoid DoS conditions
- WebScanner is designed for security testing, not malicious use

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.