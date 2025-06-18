import requests

def scan_weak_passwords(url):
    response = requests.get(url)
    if "password" in response.text.lower():
        print("[!] Weak password policy detected.")
        return True
    print("[+] No weak password policy detected.")
    return False
