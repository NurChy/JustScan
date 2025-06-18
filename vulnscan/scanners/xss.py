import requests

def scan_xss(url):
    """Scans a URL for basic XSS vulnerabilities."""
    test_payload = "<script>alert('xss')</script>"
    try:
        response = requests.get(f"{url}?q={test_payload}")
        if test_payload in response.text:
            print("[!] Potential XSS vulnerability detected!")
            return True
        else:
            print("[+] No XSS vulnerability found.")
            return False
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False

