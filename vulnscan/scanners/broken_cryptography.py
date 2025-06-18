import requests

def scan_broken_cryptography(url):
    response = requests.get(url)
    if "weak" in response.text or "MD5" in response.text:
        print("[!] Potential broken cryptography vulnerability detected.")
        return True
    print("[+] No broken cryptography vulnerabilities detected.")
    return False
