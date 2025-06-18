import requests

def scan_session_fixation(url):
    response = requests.get(url)
    if 'PHPSESSID' in response.cookies:
        print("[!] Potential session fixation vulnerability detected.")
        return True
    print("[+] No session fixation vulnerabilities detected.")
    return False
