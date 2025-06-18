import requests

def scan_host_header_injection(url):
    headers = {
        "Host": "malicious.com"
    }

    try:
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)
        if "malicious.com" in response.text or response.status_code in [301, 302, 303, 307, 308]:
            return True
    except requests.exceptions.TooManyRedirects:
        print("[!] Too many redirects detected.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")

    return False
