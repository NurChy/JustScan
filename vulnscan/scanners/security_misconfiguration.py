import requests

def scan_security_misconfiguration(url):
    response = requests.get(url)
    if "debug" in response.text or "error" in response.text:
        print("[!] Potential security misconfiguration detected.")
        return True
    print("[+] No security misconfiguration detected.")
    return False
