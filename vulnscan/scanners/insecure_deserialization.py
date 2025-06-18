import requests

def scan_insecure_deserialization(url):
    payload = "O:8:\"BadClass\":0:{}"
    response = requests.post(url, data=payload)
    if "Unserialize error" in response.text:
        print("[!] Potential insecure deserialization vulnerability detected.")
        return True
    print("[+] No insecure deserialization vulnerabilities detected.")
    return False
