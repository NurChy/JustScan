import requests

def scan_info_disclosure(url):
    keywords = ["password", "admin", "secret", "api_key", "token"]
    response = requests.get(url)
    for keyword in keywords:
        if keyword in response.text.lower():
            print(f"[!] Potential Information Disclosure: Found '{keyword}'")
            return True
    print("[+] No sensitive info disclosed.")
    return False
