import requests

def scan_command_injection(url):
    test_payload = "test; whoami"
    try:
        response = requests.get(f"{url}?cmd={test_payload}")
        if "root" in response.text or "uid=" in response.text:
            print("[!] Potential Command Injection detected!")
            return True
        else:
            print("[+] No Command Injection found.")
            return False
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False
