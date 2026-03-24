# Secure API Scanner

This is a simple Python project that scans a given URL for basic API and web security checks.

## Features
- Checks HTTPS usage
- Verifies TLS connection support
- Scans common open ports
- Checks important security headers
- Detects basic API response issues
- Saves output in JSON format

## Files
- `scanner.py` — main Python script
- `requirements.txt` — required package
- `README.md` — project documentation

## Installation
```bash
pip install -r requirements.txt
```
## Run  
```bash
python scanner.py https://api.github.com --json-out report.json
```
## Output

The scanner prints the results in the terminal and also creates a report.json file.

## Tech Stack
- Python
- requests
- ssl
- socket
