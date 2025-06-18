import requests

def scan_email_header_injection(url):
    payload = "Recipient: test@example.com\r\nSubject: Test\r\nX-Originating-IP: 127.0.0.1\r\n"
    response = requests.post(url, data=payload)
    if "Recipient:" in response.text:
        print("[!] Potential email header injection vulnerability detected.")
        return True
    print("[+] No email header injection vulnerabilities detected.")
    return False
