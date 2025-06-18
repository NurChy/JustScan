import requests

def scan_security_headers(url):
    try:
        response = requests.get(url)
        missing = []
        required = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]
        for header in required:
            if header not in response.headers:
                missing.append(header)
        if missing:
            print(f"[!] Missing Security Headers: {', '.join(missing)}")
            return True
        print("[+] All essential security headers are present.")
        return False
    except requests.RequestException as e:
        print(f"Error checking security headers: {e}")
        return False
