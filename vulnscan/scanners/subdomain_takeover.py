import requests

def scan_subdomain_takeover(url):
    response = requests.get(url)
    if "No such host is known" in response.text:
        print("[!] Potential subdomain takeover vulnerability detected.")
        return True
    print("[+] No subdomain takeover vulnerability detected.")
    return False
