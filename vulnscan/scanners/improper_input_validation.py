import requests

def scan_improper_input_validation(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"input": payload})
    if "alert('XSS')" in response.text:
        print("[!] Potential improper input validation vulnerability detected.")
        return True
    print("[+] No improper input validation vulnerabilities detected.")
    return False
