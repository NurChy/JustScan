import requests

def scan_privilege_escalation(url):
    response = requests.get(url)
    if "admin" in response.text and "privileges" in response.text:
        print("[!] Potential privilege escalation vulnerability detected.")
        return True
    print("[+] No privilege escalation vulnerabilities detected.")
    return False
