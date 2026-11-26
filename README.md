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

## Conclusion

This project gave me hands-on practice with Python automation and basic security scanning concepts. It is a beginner-friendly project, but it demonstrates practical skills related to scripting, security awareness, and project sharing through GitHub.

## Exposure Management Engineering Portfolio

Two additional, AI-assisted projects with reproducible tests and synthetic evidence:

- [Vulnerability Detection Content Lab](exposure-management-portfolio/detection-content-lab/): versioned Apache CVE rules, host/network evidence confidence, and 28 regression fixtures.
- [AI-Assisted Vulnerability Triage](exposure-management-portfolio/ai-vulnerability-triage/): explainable risk prioritization, optional local Ollama advice, and human-reviewed work-item export.

See the [portfolio guide](exposure-management-portfolio/) for setup, reports, limitations, and interview demonstrations.
