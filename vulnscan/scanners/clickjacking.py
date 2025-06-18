import requests

def scan_clickjacking(url):
    response = requests.get(url)
    if "X-Frame-Options" not in response.headers:
        print("[!] Potential Clickjacking vulnerability detected.")
        return True
    print("[+] No Clickjacking vulnerabilities detected.")
    return False
