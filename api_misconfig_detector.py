import argparse
import requests
from urllib.parse import urlparse

# Common error keywords to detect potential information leakage in API responses
ERROR_KEYWORDS = [
    "exception",
    "traceback",
    "stack trace",
    "select ",
    "sql syntax",
    "pdoexception",
    "nullreferenceexception",
    "keyerror",
    "valueerror",
]

def parse_args():

    """Parse command-line arguments.
    URL is optional – if not provided, a default test URL is used."""
    parser = argparse.ArgumentParser(description="Simple API Misconfiguration Detector")
    parser.add_argument(
        "url",
        nargs="?",  # URL becomes optional
        default="https://example.com",  # default URL if none is provided
        help="Base URL of the API endpoint to test",
    )
    return parser.parse_args()


"""Test whether the API endpoint is accessible without authentication"""
def test_missing_auth(url: str):
    # Send a simple GET request without headers
    print("\n[TEST] Missing authentication / open access")
    try:
        resp = requests.get(url, timeout=5)
    except Exception as e:
        print(f"  [!] Request failed: {e}")
        return
    # Check if the endpoint returns 200 without auth → may indicate weak access control
    print(f"  [*] Status code: {resp.status_code}")
    if resp.status_code == 200:
        print("  [!] Endpoint returned 200 without any auth – might be too permissive.")
    elif resp.status_code in (401, 403):
        print("  [+] Endpoint requires authentication (401/403) – looks fine.")
    else:
        print("  [*] Got non-standard status code, needs manual review.")

# Check if the API leaks internal error messages when receiving unexpected input
def test_error_leakage(url: str):
    print("\n[TEST] Error leakage / verbose error messages")
    try:
        resp = requests.get(url, params={"test": "''' OR 1=1 --"}, timeout=5)
    except Exception as e:
        print(f"  [!] Request failed: {e}")
        return

    print(f"  [*] Status code: {resp.status_code}")
    body = resp.text or ""
    leaked = [kw for kw in ERROR_KEYWORDS if kw in body.lower()]

    if leaked:
        print("  [!] Possible information leakage detected:")
        for kw in leaked:
            print(f"      - Found keyword: {kw}")
    else:
        print("  [+] No obvious error keywords found.")

# Build a URL attempt containing ... to test for path traversal vulnerabilities
def build_traversal_url(url: str) -> str:
    # Try to append ../ to the path part
    parsed = urlparse(url)
    base = parsed.geturl()
    if not base.endswith("/"):
        base += "/"
    return base + "../.."

# Attempt path traversal to check if the server exposes files outside its directory
def test_path_traversal(url: str):
    print("\n[TEST] Path traversal attempts")
    payload_url = build_traversal_url(url)
    # Inspect response for sensitive keywords that indicate exposed system paths
    try:
        resp = requests.get(payload_url, timeout=5)
    except Exception as e:
        print(f"  [!] Request failed: {e}")
        return

    print(f"  [*] Tried URL: {payload_url}")
    print(f"  [*] Status code: {resp.status_code}")
    snippet = (resp.text or "")[:300].lower()

    if resp.status_code == 200 and any(x in snippet for x in ["root", "etc/passwd", "users"]):
        print("  [!] Suspicious: got 200 and sensitive-looking content – might be traversal.")
    else:
        print("  [*] No obvious traversal behavior detected (but still needs manual review).")

# Test how the API responds to different HTTP methods (GET/POST/PUT/DELETE)
def test_http_methods(url: str):
    print("\n[TEST] HTTP methods behavior")

    methods = ["GET", "POST", "PUT", "DELETE"]
    for method in methods:
        try:
            if method == "GET":
                resp = requests.get(url, timeout=5)
            elif method == "POST":
                resp = requests.post(url, json={"test": "data"}, timeout=5)
            elif method == "PUT":
                resp = requests.put(url, json={"test": "data"}, timeout=5)
            elif method == "DELETE":
                resp = requests.delete(url, timeout=5)
        except Exception as e:
            print(f"  [!] {method}: request failed: {e}")
            continue

        print(f"  [*] {method}: status {resp.status_code}")
        if method != "GET" and resp.status_code == 200:
            print(f"  [!] {method} returned 200 – endpoint might allow unintended modifications.")

# Main entry point: run all security tests on the provided URL
def main():
    args = parse_args()
    base_url = args.url.strip()
    print(f"[+] Testing endpoint: {base_url}")
    test_missing_auth(base_url)
    test_error_leakage(base_url)
    test_path_traversal(base_url)
    test_http_methods(base_url)


if __name__ == "__main__":
    main()
