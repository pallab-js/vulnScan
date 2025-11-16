# WebScanner

A CLI-based web security vulnerability scanner.

## Features

- Security checks for common web vulnerabilities
- Multiple output formats: console, JSON, XML, CSV
- Configurable scanning parameters
- Multi-threaded scanning
- Plugin system for custom checks

## Installation

```bash
git clone https://github.com/yourusername/webscanner.git
cd webscanner
pip install -r requirements.txt
python setup.py install
```

## Usage

### Basic Scan
```bash
webscanner http://example.com
```

### Usage Examples
```bash
webscanner http://example.com
webscanner https://example.com --output json --threads 5
webscanner http://example.com --checks header_checks,file_checks
```



## Checks

- Security headers
- Server information and vulnerabilities
- File enumeration
- HTTP methods and cookies

## Output Formats

- Console (default)
- JSON
- XML
- CSV



## Configuration

Use JSON config files. Example:

```json
{
  "scanner": {
    "threads": 10,
    "timeout": 30
  }
}
```

## Performance

- Adjust threads and delays
- Use rate limiting
- Save/load results for long scans



