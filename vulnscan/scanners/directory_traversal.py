import requests

def scan_directory_traversal(url):
    test_payload = "../../etc/passwd"
    response = requests.get(f"{url}?file={test_payload}")
    if "root:x:" in response.text:
        print("[!] Potential Directory Traversal vulnerability detected!")
        return True
    print("[+] No Directory Traversal vulnerability found.")
    return False
