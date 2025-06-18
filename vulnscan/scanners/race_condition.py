import requests

def scan_race_condition(url):
    response = requests.get(url)
    if "404 Not Found" in response.text:
        print("[!] Potential race condition vulnerability detected.")
        return True
    print("[+] No race condition vulnerabilities detected.")
    return False
