import argparse
import json
import socket
import ssl
from urllib.parse import urlparse

import requests

COMMON_PORTS = [80, 443, 22, 8080, 8443]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def check_tls(hostname: str, port: int = 443) -> dict:
    result = {"supported": False, "version": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["supported"] = True
                result["version"] = ssock.version()
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ports(hostname: str, ports: list[int]) -> list[dict]:
    results = []
    for port in ports:
        status = "closed"
        try:
            with socket.create_connection((hostname, port), timeout=1.5):
                status = "open"
        except Exception:
            pass
        results.append({"port": port, "status": status})
    return results


def scan(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme

    report = {
        "target": url,
        "https_enabled": scheme == "https",
        "tls": check_tls(hostname) if hostname else {"supported": False, "version": None, "error": "Invalid hostname"},
        "ports": check_ports(hostname, COMMON_PORTS) if hostname else [],
        "http": {},
        "issues": [],
    }

    try:
        response = requests.get(url, timeout=5)
        headers = dict(response.headers)
        missing_headers = [h for h in SECURITY_HEADERS if h not in headers]

        report["http"] = {
            "status_code": response.status_code,
            "content_type": headers.get("Content-Type"),
            "server": headers.get("Server"),
            "security_headers_present": {h: headers.get(h) for h in SECURITY_HEADERS if h in headers},
            "security_headers_missing": missing_headers,
            "is_json": "application/json" in headers.get("Content-Type", ""),
        }

        if response.status_code >= 400:
            report["issues"].append(f"HTTP error status detected: {response.status_code}")
        if missing_headers:
            report["issues"].append("Missing security headers: " + ", ".join(missing_headers))
        if not report["http"]["is_json"]:
            report["issues"].append("Response does not appear to be JSON")
        if headers.get("Server"):
            report["issues"].append("Server header exposed")
        if scheme != "https":
            report["issues"].append("Target does not use HTTPS")
        if not report["tls"].get("supported"):
            report["issues"].append("TLS handshake failed or not supported")
        open_ports = [str(p["port"]) for p in report["ports"] if p["status"] == "open"]
        if open_ports:
            report["issues"].append("Open common ports found: " + ", ".join(open_ports))

    except requests.RequestException as e:
        report["http"] = {"error": str(e)}
        report["issues"].append(f"HTTP request failed: {e}")

    return report


def print_report(report: dict) -> None:
    print("=" * 60)
    print("Secure API Scanner")
    print("=" * 60)
    print(f"Target: {report['target']}")
    print(f"HTTPS Enabled: {report['https_enabled']}")
    print(f"TLS Supported: {report['tls']['supported']}")
    if report['tls'].get('version'):
        print(f"TLS Version: {report['tls']['version']}")
    if report['tls'].get('error'):
        print(f"TLS Error: {report['tls']['error']}")

    print("\nPorts:")
    for item in report["ports"]:
        print(f"  - {item['port']}: {item['status']}")

    print("\nHTTP:")
    if "error" in report["http"]:
        print(f"  Error: {report['http']['error']}")
    else:
        print(f"  Status Code: {report['http']['status_code']}")
        print(f"  Content-Type: {report['http']['content_type']}")
        print(f"  Server: {report['http']['server']}")
        print("  Missing Security Headers:")
        for h in report["http"]["security_headers_missing"]:
            print(f"    - {h}")

    print("\nIssues:")
    if report["issues"]:
        for issue in report["issues"]:
            print(f"  - {issue}")
    else:
        print("  No obvious issues found")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple Secure API Scanner")
    parser.add_argument("url", help="Target URL, example: https://api.github.com")
    parser.add_argument("--json-out", help="Optional output file, example: report.json")
    args = parser.parse_args()

    report = scan(args.url)
    print_report(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report saved to: {args.json_out}")


if __name__ == "__main__":
    main()
