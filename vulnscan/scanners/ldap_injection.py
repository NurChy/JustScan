import requests

def scan_ldap_injection(url):
    payload = "(uid=*))(|(uid=*))"
    response = requests.get(url, params={"search": payload})
    if "LDAP search error" in response.text:
        print("[!] Potential LDAP injection vulnerability detected.")
        return True
    print("[+] No LDAP injection vulnerabilities detected.")
    return False
