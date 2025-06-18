import requests

def scan_open_redirect(url):
    test_payload = "https://evil.com"
    response = requests.get(f"{url}?redirect={test_payload}", allow_redirects=False)
    if "Location" in response.headers and test_payload in response.headers["Location"]:
        print("[!] Potential Open Redirect detected!")
        return True
    print("[+] No Open Redirect vulnerability found.")
    return False