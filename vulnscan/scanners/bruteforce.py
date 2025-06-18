import requests

def scan_bruteforce(url):
    response = requests.get(url)
    if "Login" in response.text and "password" in response.text:
        print("[!] Potential Brute Force vulnerability: Login form detected.")
        return True
    print("[+] No brute force vulnerabilities detected.")
    return False
