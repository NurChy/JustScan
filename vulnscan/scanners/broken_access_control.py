import requests

def scan_broken_access_control(url):
    response = requests.get(url)
    if "admin" in response.text and "access control" in response.text:
        print("[!] Potential broken access control vulnerability detected.")
        return True
    print("[+] No broken access control vulnerabilities detected.")
    return False

